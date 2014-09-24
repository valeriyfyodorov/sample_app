class User < ActiveRecord::Base
	#uncomment one and comment the second to enable secure_passwords of 'bcrypt-ruby' gem
	has_secure_password
    #attr_accessor :password, :password_confirmation         

	before_save { self.email = email.downcase }
	validates :name,  presence: true, length: { maximum: 50 }
	VALID_EMAIL_REGEX = /\A[\w+\-.]+@[a-z\d\-]+(?:\.[a-z\d\-]+)*\.[a-z]+\z/i
	validates :email, presence: true, 
						format: { with: VALID_EMAIL_REGEX },
                    	uniqueness: { case_sensitive: false }
    validates :password, length: { minimum: 6 }
        
end
