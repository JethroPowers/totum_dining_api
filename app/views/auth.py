from . import auth_blueprint

from flask.views import MethodView
from flask import make_response, request, jsonify
from app.models.user import User
import phonenumbers
import re

class RegistrationView(MethodView):
    """This class registers a new user."""

    def post(self):
        """Handle POST request for this view. Url ---> /auth/register"""
        try:
            post_data = request.data
            # Query to see if the user already exists
            email = request.data.get("email", "").strip()
            if not email:
                response = {
                    'message': 'Please enter an email'
                }
                return make_response(jsonify(response)), 400
            email_regex = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
            if not (re.match(email_regex, email)):
                response = {
                    'message': 'Please enter a valid email'
                }
                return make_response(jsonify(response)), 400
            user = User.query.filter_by(email=email).first()
            if user:
                # There is an existing user. We don't want to register users twice
                # Return a message to the user telling them that they they already exist
                response = {
                    'message': 'User already exists. Please login.'
                }

                return make_response(jsonify(response)), 409

            password = post_data.get("password", "").strip()
            if not password:
                response = {
                    'message': 'Please enter a password'
                }
                return make_response(jsonify(response)), 400
            password_reg = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!#%*?&]{6,20}$"
            compile_pat = re.compile(password_reg)
            passord_check = re.search(compile_pat, password)
            if not passord_check:
                response = {
                    'message': 'Please enter a valid password'
                }
                return make_response(jsonify(response)), 400

            full_name = post_data.get("full_name", "").strip()
            if not full_name:
                response = {
                    'message': 'Please enter your full name'
                }
                return make_response(jsonify(response)), 400
            fullname_reg = '[A-Za-z]{2,25}( [A-Za-z]{2,25})?'
            compile_reg = re.compile(fullname_reg)
            name_check = re.search(compile_reg, fullname_reg)
            if not name_check:
                response = {
                    'message': 'Please enter a valid full name'
                }
                return make_response(jsonify(response)), 400
            phone = post_data.get("phone")
            if phone is not None:
                phone = phone.strip()
                try:
                    user_phone = phonenumbers.parse(phone)
                    valid_number = phonenumbers.is_valid_number(user_phone)
                    if not valid_number:
                        raise phonenumbers.NumberParseException(100, "invalid number")
                except phonenumbers.NumberParseException:
                    response = {
                        'message': 'Please enter a valid phone number'
                    }
                    return make_response(jsonify(response)), 400

            user = User(email=email, password=password, full_name=full_name, phone=phone)
            user.save()

            response = {
                'message': 'You registered successfully. Please log in.'
            }
            # return a response notifying the user that they registered successfully
            return make_response(jsonify(response)), 201
        except Exception as e:
            # An error occured, therefore return a string message containing the error
            response = {
                'message': str(e)
            }
            return make_response(jsonify(response)), 400



class LoginView(MethodView):
    """This class-based view handles user login and access token generation."""

    def post(self):
        """Handle POST request for this view. Url ---> /auth/login"""
        try:
            # Get the user object using their email (unique to every user)
            user = User.query.filter_by(email=request.data['email'].strip()).first()


            # Try to authenticate the found user using their password
            if user and user.password_is_valid(request.data['password'].strip()):
                # Generate the access token. This will be used as the authorization header
                access_token = user.generate_token(user.id)
                if access_token:
                    response = {
                        'message': 'You logged in successfully.',
                        'access_token': access_token.decode()
                    }
                    return make_response(jsonify(response)), 200
            else:
                # User does not exist. Therefore, we return an error message
                response = {
                    'message': 'Invalid email or password, Please try again'
                }
                return make_response(jsonify(response)), 401

        except Exception as e:
            # Create a response containing an string error message
            response = {
                'message': str(e)
            }
            # Return a server error using the HTTP Error Code 500 (Internal Server Error)
            return make_response(jsonify(response)), 500

registration_view = RegistrationView.as_view('registration_view')
login_view = LoginView.as_view('login_view')

# Define the rule for the registration url --->  /auth/register
# Then add the rule to the blueprint
auth_blueprint.add_url_rule(
    '/auth/register',
    view_func=registration_view,
    methods=['POST'])

# Define the rule for the registration url --->  /auth/login
# Then add the rule to the blueprint
auth_blueprint.add_url_rule(
    '/auth/login',
    view_func=login_view,
    methods=['POST']
)