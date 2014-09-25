class User < ActiveRecord::Base
	#uncomment one and comment the second to enable secure_passwords of 'bcrypt-ruby' gem
	has_secure_password
    #attr_accessor :password, :password_confirmation         

	before_save { self.email = email.downcase }
	before_create :create_remember_token

	validates :name,  presence: true, length: { maximum: 50 }
	VALID_EMAIL_REGEX = /\A[\w+\-.]+@[a-z\d\-]+(?:\.[a-z\d\-]+)*\.[a-z]+\z/i
	validates :email, presence: true, 
						format: { with: VALID_EMAIL_REGEX },
                    	uniqueness: { case_sensitive: false }
    validates :password, length: { minimum: 6 }


    def create
    user = User.find_by(email: params[:session][:email].downcase)
    if user && user.authenticate(params[:session][:password])
      sign_in user
      redirect_to user
    else
      flash.now[:error] = 'Invalid email/password combination'
      render 'new'
    end
  end

    def User.new_remember_token
      SecureRandom.urlsafe_base64
    end

    def User.digest(token)
      Digest::SHA1.hexdigest(token.to_s)
    end

    private

    def create_remember_token
      self.remember_token = User.digest(User.new_remember_token)
    end        
end
