"""
This module takes care of starting the API Server, Loading the DB and Adding the endpoints
"""
from flask import Flask, request, jsonify, url_for, Blueprint
from api.models import db, User
from api.utils import generate_sitemap, APIException
from flask_bcrypt import Bcrypt
from flask_jwt_extended import create_access_token
from flask_jwt_extended import jwt_required


api = Blueprint('api', __name__)


@api.route('/hello', methods=['POST', 'GET'])
def handle_hello():

    response_body = {
        "message": "Hello! I'm a message that came from the backend, check the network tab on the google inspector and you will see the GET request"
    }

    return jsonify(response_body), 200

@api.route("/signup", methods=["POST"])
def signup():
    data = request.get_json()
    print(data)
    new_user = User.query.filter_by(email=data["email"]).first()
    if (new_user is not None):
        return jsonify({
            "msg":"Email registrado"
        }),400
    secure_password = bcrypt.generate_password_hash(
        data["password"],rounds = None).decode("utf-8")
    new_user = User(email = data["email"],
                    password = secure_password, is_active=True)
    db.session.add(new_user)
    db.session.commit()
    return jsonify(new_user.serialize()), 201

@api.route("/login", methods=["POST"])
def user_login():
    user_email = request.json.get("email")
    user_password = request.json.get("password")
    # buscar el usuario por el correo
    user = User.query.filter_by(email=user_email).first()
    if user is None:
        return jsonify({"message": "User no found"}), 401
    
    #verificar la clave
    if not bcrypt.check_password_hash(user.password, user_password):
        return jsonify({"message": "Wrong password"}),401
    #generar el token
    acces_token = create_access_token(identify=user.id)
    #retornar el token
    return jsonify({"accessToken": acces_token})

@api.route("/helloprotected",methods=['GET'])
@jwt_required()
def hello_protected_get():
    user_id= get_jwt_identity()
    return jsonify({
        "userId": user_id,
        "message": "Hello protected routed"
    })
    
