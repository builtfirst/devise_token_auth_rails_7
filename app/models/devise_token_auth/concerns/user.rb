# frozen_string_literal: true

module DeviseTokenAuth::Concerns::User
  extend ActiveSupport::Concern

  MAX_SCREENSHOT_TOKENS = 4.freeze
  MAX_CLIENT_TOKENS = DeviseTokenAuth.max_number_of_devices - MAX_SCREENSHOT_TOKENS.freeze

  def self.tokens_match?(token_hash, token)
    @token_equality_cache ||= {}

    key = "#{token_hash}/#{token}"
    result = @token_equality_cache[key] ||= DeviseTokenAuth::TokenFactory.token_hash_is_token?(token_hash, token)
    @token_equality_cache = {} if @token_equality_cache.size > 10000
    result
  end

  included do
    # Hack to check if devise is already enabled
    if method_defined?(:devise_modules)
      devise_modules.delete(:omniauthable)
    else
      devise :database_authenticatable, :registerable,
             :recoverable, :validatable, :confirmable
    end

    if const_defined?('ActiveRecord') && ancestors.include?(ActiveRecord::Base)
      include DeviseTokenAuth::Concerns::ActiveRecordSupport
    end

    if const_defined?('Mongoid') && ancestors.include?(Mongoid::Document)
      include DeviseTokenAuth::Concerns::MongoidSupport
    end

    if DeviseTokenAuth.default_callbacks
      include DeviseTokenAuth::Concerns::UserOmniauthCallbacks
    end

    # get rid of dead tokens
    before_save :destroy_expired_tokens

    # remove old tokens if password has changed
    before_save :remove_tokens_after_password_reset

    # don't use default devise email validation
    def email_required?; false; end
    def email_changed?; false; end
    def will_save_change_to_email?; false; end

    if DeviseTokenAuth.send_confirmation_email && devise_modules.include?(:confirmable)
      include DeviseTokenAuth::Concerns::ConfirmableSupport
    end

    def password_required?
      return false unless provider == 'email'
      super
    end

    # override devise method to include additional info as opts hash
    def send_confirmation_instructions(opts = {})
      generate_confirmation_token! unless @raw_confirmation_token

      # fall back to "default" config name
      opts[:client_config] ||= 'default'
      opts[:to] = unconfirmed_email if pending_reconfirmation?
      opts[:redirect_url] ||= DeviseTokenAuth.default_confirm_success_url

      send_devise_notification(:confirmation_instructions, @raw_confirmation_token, opts)
    end

    # override devise method to include additional info as opts hash
    def send_reset_password_instructions(opts = {})
      token = set_reset_password_token

      # fall back to "default" config name
      opts[:client_config] ||= 'default'

      send_devise_notification(:reset_password_instructions, token, opts)
      token
    end

    # override devise method to include additional info as opts hash
    def send_unlock_instructions(opts = {})
      raw, enc = Devise.token_generator.generate(self.class, :unlock_token)
      self.unlock_token = enc
      save(validate: false)

      # fall back to "default" config name
      opts[:client_config] ||= 'default'

      send_devise_notification(:unlock_instructions, raw, opts)
      raw
    end

    def create_token(client: nil, lifespan: nil, cost: nil, **token_extras)
      token_extras = yield token_extras if block_given?
      token = DeviseTokenAuth::TokenFactory.create(client: client, lifespan: lifespan, cost: cost)

      tokens[token.client] = {
        token:  token.token_hash,
        expiry: token.expiry
      }.merge!(token_extras)

      clean_old_tokens

      token
    end
  end

  def valid_token?(token, client = 'default')
    return false unless tokens[client]
    return true if token_is_current?(token, client)
    return true if token_can_be_reused?(token, client)

    # return false if none of the above conditions are met
    false
  end

  # this must be done from the controller so that additional params
  # can be passed on from the client
  def send_confirmation_notification?; false; end

  def token_is_current?(token, client)
    # ghetto HashWithIndifferentAccess
    expiry     = tokens[client]['expiry'] || tokens[client][:expiry]
    token_hash = tokens[client]['token'] || tokens[client][:token]
    previous_token_hash = tokens[client]['previous_token'] || tokens[client][:previous_token]

    return true if (
      # ensure that expiry and token are set
      expiry && token &&

      # ensure that the token has not yet expired
      DateTime.strptime(expiry.to_s, '%s') > Time.zone.now &&

      # ensure that the token is valid
      (
        # check if the latest token matches
        does_token_match?(token_hash, token) ||

        # check if the previous token matches
        does_token_match?(previous_token_hash, token)
      )
    )
  end

  # check if the hash of received token matches the stored token
  def does_token_match?(token_hash, token)
    return false if token_hash.nil?

    DeviseTokenAuth::Concerns::User.tokens_match?(token_hash, token)
  end

  # allow batch requests to use the last token
  def token_can_be_reused?(token, client)
    # ghetto HashWithIndifferentAccess
    updated_at = tokens[client]['updated_at'] || tokens[client][:updated_at]
    last_token_hash = tokens[client]['last_token'] || tokens[client][:last_token]

    return true if (
      # ensure that the last token and its creation time exist
      updated_at && last_token_hash &&

      # ensure that last token falls within the batch buffer throttle time of the last request
      updated_at.to_time > Time.zone.now - DeviseTokenAuth.batch_request_buffer_throttle &&

      # ensure that the token is valid
      DeviseTokenAuth::TokenFactory.token_hash_is_token?(last_token_hash, token)
    )
  end

  # update user's auth token (should happen on each request)
  def create_new_auth_token(client = nil)
    now = Time.zone.now

    token = create_token(
      client: client,
      previous_token: tokens.fetch(client, {})['token'],
      last_token: tokens.fetch(client, {})['previous_token'],
      updated_at: now
    )

    update_auth_headers(token.token, token.client)
  end

  def build_auth_headers(token, client = 'default')
    # client may use expiry to prevent validation request if expired
    # must be cast as string or headers will break
    expiry = tokens[client]['expiry'] || tokens[client][:expiry]
    headers = {
      DeviseTokenAuth.headers_names[:"access-token"] => token,
      DeviseTokenAuth.headers_names[:"token-type"]   => 'Bearer',
      DeviseTokenAuth.headers_names[:"client"]       => client,
      DeviseTokenAuth.headers_names[:"expiry"]       => expiry.to_s,
      DeviseTokenAuth.headers_names[:"uid"]          => uid
    }
    headers.merge(build_bearer_token(headers))
  end

  def build_bearer_token(auth)
    return {} if DeviseTokenAuth.cookie_enabled # There is no need for the bearer token if it is using cookies

    encoded_token = Base64.strict_encode64(auth.to_json)
    bearer_token = "Bearer #{encoded_token}"
    { DeviseTokenAuth.headers_names[:"authorization"] => bearer_token }
  end

  def update_auth_headers(token, client = 'default', screenshot = false)
    headers = build_auth_headers(token, client)
    clean_old_tokens(screenshot)
    save!

    headers
  end

  def build_auth_url(base_url, args)
    args[:uid]    = uid
    args[:expiry] = tokens[args[:client_id]]['expiry']

    DeviseTokenAuth::Url.generate(base_url, args)
  end

  def extend_batch_buffer(token, client)
    tokens[client]['updated_at'] = Time.zone.now
    update_auth_headers(token, client)
  end

  def confirmed?
    devise_modules.exclude?(:confirmable) || super
  end

  def token_validation_response
    as_json(except: %i[tokens created_at updated_at])
  end

  protected

  def destroy_expired_tokens
    if tokens
      tokens.delete_if do |cid, v|
        expiry = v[:expiry] || v['expiry']
        DateTime.strptime(expiry.to_s, '%s') < Time.zone.now
      end
    end
  end

  def should_remove_tokens_after_password_reset?
    DeviseTokenAuth.remove_tokens_after_password_reset &&
      (respond_to?(:encrypted_password_changed?) && encrypted_password_changed?)
  end

  def remove_tokens_after_password_reset
    return unless should_remove_tokens_after_password_reset?

    if tokens.present? && tokens.many?
      client, token_data = tokens.max_by { |cid, v| v[:expiry] || v['expiry'] }
      self.tokens = { client => token_data }
    end
  end

  def max_client_tokens_exceeded?
    # remove the slots for max_screen_shot_tokens
    client_tokens.length > MAX_CLIENT_TOKENS
  end

  def clean_old_tokens(screenshot = false)
    return unless tokens.present?
    return clean_old_screenshot_tokens if screenshot
    

    if max_client_tokens_exceeded?
      client_tokens = tokens.select { |cid, v| !v["screenshot"] && !v[:screenshot] }
      # Sort client tokens by expiry and convert back to a hash
      sorted_client_tokens = client_tokens.sort_by { |_cid, v| v[:expiry] || v['expiry'] }.to_h

      # Remove the oldest token until the count is within the maximum limit
      while sorted_client_tokens.length > MAX_CLIENT_TOKENS
        oldest_token = sorted_client_tokens.keys.first
        sorted_client_tokens.delete(oldest_token)
        self.tokens.delete(oldest_token)
      end
    end
  end

  private

  def client_tokens 
    tokens.select { |cid, v| !v["screenshot"] && !v[:screenshot] }
  end

  def clean_old_screenshot_tokens
    # Select tokens that are marked as screenshots
    screenshot_tokens = tokens.select { |cid, v| v["screenshot"] || v[:screenshot] }
    # Check if the number of screenshot tokens exceeds the maximum allowed
    if screenshot_tokens.length >= MAX_SCREENSHOT_TOKENS
      # Sort screenshot tokens by expiry and convert back to a hash
      sorted_screenshot_tokens = screenshot_tokens.sort_by { |_cid, v| v[:expiry] || v['expiry'] }.to_h

      # Remove the oldest token until the count is within the maximum limit
      while sorted_screenshot_tokens.length > MAX_SCREENSHOT_TOKENS
        oldest_token = sorted_screenshot_tokens.keys.first
        sorted_screenshot_tokens.delete(oldest_token)
        self.tokens.delete(oldest_token)
      end
    end
  end
end
