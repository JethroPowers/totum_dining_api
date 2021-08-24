from . import auth_blueprint

from flask.views import MethodView
from flask_bcrypt import Bcrypt
from flask import make_response, request, jsonify
from app.models.user import User
import phonenumbers
import re


class UsersView(MethodView):

    def post(self):
        """Handle POST request for this view. Url ---> /users"""
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

                return make_response(jsonify(response)), 400

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
            is_admin = post_data.get("is_admin")
            try:
                is_admin = int(is_admin)
            except ValueError:
                response = {
                    'message': 'is_admin must be either 0 or 1'
                }

                return make_response(jsonify(response)), 400
            except TypeError:
                response = {
                    'message': 'is_admin is not provided, must be either 0 or 1 '
                }

                return make_response(jsonify(response)), 400

            if not( is_admin == 1 or is_admin == 0):
                response = {
                    'message': 'is_admin must be either 0 or 1'
                }
                return make_response(jsonify(response)), 400

            user = User(email=email, password=password, full_name=full_name, phone=phone, is_admin=is_admin)
            user.save()

            access_token = user.generate_token(user.user_id)
            user_dic = {
                'id': user.user_id,
                'full_name': user.full_name,
                'is_admin': user.is_admin,
                'email': user.email,
                'phone': user.phone
            }

            response = {
                'message': 'You registered successfully.',
                'access_token': access_token.decode(),
                'user': user_dic
            }
            # return a response notifying the user that they registered successfully
            return make_response(jsonify(response)), 201
        except Exception as e:
            # An error occured, therefore return a string message containing the error
            response = {
                'message': str(e)
            }
            return make_response(jsonify(response)), 400

    def put(self):
        auth_header = request.headers.get('Authorization')
        if auth_header is None:
            response = jsonify({
                'message': f'Authorization header missing',
                'status': 'error'
            })
            response.status_code = 401
            return response
        if auth_header == '':
            response = jsonify({
                'message': f'Please insert Bearer token',
                'status': 'error'
            })
            response.status_code = 401
            return response
        access_token = auth_header.split(" ")
        if len(access_token) < 2:
            response = jsonify({
                'message': f'Authorization token should start with keyword Bearer',
                'status': 'error'
            })
            response.status_code = 401
            return response
        access_token = auth_header.split(" ")[1]
        if access_token:
            # Get the user id related to this access token
            user_id, code = User.decode_token(access_token)
            if code == 1:
                response = jsonify({
                    'message': f'Expired token. Please login to get a new token',
                    'status': 'error'
                })
                response.status_code = 401
                return response
            elif code == 2:
                response = jsonify({
                    'message': f'Invalid token. Please register or login',
                    'status': 'error'
                })
                response.status_code = 401
                return response

        else:
            response = jsonify({
                'message': f'Please enter an access token',
                'status': 'error'
            })
            response.status_code = 401
            return response

        user = User.query.get(user_id)

        post_data = request.data

        email = post_data.get("email", "").strip()
        if email:
            email_regex = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
            if not (re.match(email_regex, email)):
                response = {
                    'message': 'Please enter a valid email'
                }
                return make_response(jsonify(response)), 400
            user.email = email
        new_password = post_data.get("new_password", "").strip()
        current_password = post_data.get("current_password", "").strip()
        if new_password:
            password_reg = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!#%*?&]{6,20}$"
            compile_pat = re.compile(password_reg)
            password_check = re.search(compile_pat, new_password)
            if not password_check:
                response = {
                    'message': 'Please enter a valid password'
                }
                return make_response(jsonify(response)), 400
            if not user.is_password_equal(current_password.strip()):
                response = {
                    'message': 'the current password is incorrect, please enter'
                               ' your current password to change your password'
                }
                return make_response(jsonify(response)), 400
            user.password = Bcrypt().generate_password_hash(new_password).decode()

        full_name = post_data.get("full_name", "").strip()
        if full_name:
            fullname_reg = '[A-Za-z]{2,25}( [A-Za-z]{2,25})?'
            compile_reg = re.compile(fullname_reg)
            name_check = re.search(compile_reg, fullname_reg)
            if not name_check:
                response = {
                    'message': 'Please enter a valid full name'
                }
                return make_response(jsonify(response)), 400
            user.full_name = full_name
        phone = post_data.get("phone", "").strip()
        if phone:
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
            user.phone = phone
        user.save()

        user_dic = {
            'id': user.user_id,
            'full_name': user.full_name,
            'is_admin': user.is_admin,
            'email': user.email,
            'phone': user.phone
        }
        response = jsonify({
            'message': f'success',
            'user': user_dic
        })
        response.status_code = 200
        return response


class LoginView(MethodView):
    """This class-based view handles user login and access token generation."""

    def post(self):
        """Handle POST request for this view. Url ---> /auth/login"""
        try:
            # Get the user object using their email (unique to every user)
            email = request.data.get("email", "").strip()
            if not email:
                response = {
                    'message': 'Please enter an email'
                }
                return make_response(jsonify(response)), 400
            user = User.query.filter_by(email=request.data['email'].strip()).first()

            # Try to authenticate the found user using their password
            password = request.data.get("password", "").strip()
            if not password:
                response = {
                    'message': 'Please enter a password'
                }
                return make_response(jsonify(response)), 400

            if user and user.is_password_equal(request.data['password'].strip()):
                # Generate the access token. This will be used as the authorization header

                access_token = user.generate_token(user.user_id)
                if access_token:
                    user_dic ={
                        'id': user.user_id,
                        'full_name': user.full_name,
                        'is_admin': user.is_admin,
                        'email': user.email,
                        'phone': user.phone
                    }
                    response = {
                        'message': 'You logged in successfully.',
                        'access_token': access_token.decode(),
                        'user': user_dic
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
            print(response)
            return make_response(jsonify(response)), 500

users_view = UsersView.as_view('users_view')
login_view = LoginView.as_view('login_view')

# Define the rule for the registration url --->  /users
# Then add the rule to the blueprint
auth_blueprint.add_url_rule(
    '/users',
    view_func=users_view,
    methods=['POST', 'PUT'])


# Define the rule for the registration url --->  /auth/login
# Then add the rule to the blueprint
auth_blueprint.add_url_rule(
    '/auth/login',
    view_func=login_view,
    methods=['POST']
)