from functools import wraps
from flask import Flask,request,make_response
from flask import jsonify
from flask_httpauth import HTTPBasicAuth
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import json
from random import randint, randrange
app = Flask(__name__)
auth = HTTPBasicAuth()
db=[]
mails=[]
Loggedin=False
Eids=[]
def genrateEid():
	return randint(100,999)

isAdmin=False
def token_required(f):
	@wraps(f)
	def decorated(*args, **kwargs):
		token = None
		# isAdmin=False 
		# jwt is passed in the request header
		if 'x-access-token' in request.headers:
			token = request.headers['x-access-token']
			print("Heloo")
		# return 401 if token is not passed
		if not token:
			return jsonify({'message' : 'Token is missing !!'}), 401
		current_user="none"
		
		try:
			data = jwt.decode(token,key="secret",algorithms=["HS256"])
			# data = jwt.decode(token, app.config['SECRET_KEY'],algorithms=["HS256"],verify=False)
	
			if(data["role"]=="ADMIN"):
					global isAdmin
					isAdmin=True
		except:
			return jsonify({'message' : 'Token is invalid !!'}), 401

		return  f(*args, **kwargs)

	return decorated



@app.route('/login', methods =['POST'])
def login():
	
	data = json.loads(request.data)
	Email= data['email']
	Password = data['password']
	# print(data,Email,Password)
	if not data or not Email or not Password:
		return make_response('Could not verify',401,{'WWW-Authenticate' : 'Basic realm ="Login required !!"'}
		)


	if Email not in mails:
		# returns 401 if user does not exist
		return make_response(
			'Could not verify',
			401,
			{'WWW-Authenticate' : 'Basic realm ="User does not exist !!"'}
		)
	
	user={}
	password=None
	for i in db:
		if(i['email']==Email):
			password=i["password"]
			user=i
			
	if check_password_hash(password,Password):
		global Loggedin
		Loggedin=True
		payload= {            
			"Eid":user["Eid"],
			"email":user["email"],
			"role":user["role"]
		}
		global isAdmin
		isAdmin=False

		token = jwt.encode(payload=payload,key="secret",algorithm="HS256")
		print(token)

		return make_response(jsonify({'token' : token}), 201)
	return make_response(
		'Could not verify',
		403,
		{'WWW-Authenticate' : 'Basic realm ="Wrong Password !!"'}
	)


@app.route('/signup', methods =['POST'])
def signup():
		data = json.loads(request.data)
		username, email= data['username'], data['email']
		password = data['password']
		
		role=data["role"]
		Eid=genrateEid()
		while(True):
			if(Eid in Eids):
				Eid=genrateEid()
			else:
				Eids.append(Eid)
				break

		if email not in mails:
			Users={}
			Users["Eid"]=Eid
			Users["username"]=username
			Users["email"]=email
			Users["role"]=role
			Users["password"]=generate_password_hash(password)
			db.append(Users)
			mails.append(email)
			print(Users)
	
			return make_response('Added Successfully.', 201)
		else:
			# returns 202 if user already exists
			return make_response('Employee already exists. Please Log in.', 202)
		
@app.route('/verify', methods =['GET'])
def verifyEmployee():
	token = None
		# isAdmin=False 
		# jwt is passed in the request header
	if 'x-access-token' in request.headers:
		token = request.headers['x-access-token']
		
	# return 401 if token is not passed
	if not token:
		return jsonify({'message' : 'Token is missing !!'}), 401
	current_user="none"
	
	try:
		data = jwt.decode(token,key="secret",algorithms=["HS256"])
		# data = jwt.decode(token, app.config['SECRET_KEY'],algorithms=["HS256"],verify=False)

		if(data["role"]=='ADMIN'):
				global isAdmin
				isAdmin=True
	except:
		return jsonify({'message' : 'Token is invalid !!'}), 401

	print(isAdmin)
	return jsonify(isAdmin)
@app.route('/addEmployee', methods =['POST'])
@token_required
def add_Employee():
	if(Loggedin):
		if(isAdmin):
			data = json.loads(request.data)
			username, email= data['username'], data['email']
			password = data['password']
		
			role=data["role"]
			Eid=genrateEid()
			while(True):
				if(Eid in Eids):
					Eid=genrateEid()
				else:
					Eids.append(Eid)
					break
			if email not in mails:
				Users={}
				Users["Eid"] = Eid
				Users["username"]=username
				Users["email"]=email
				Users["role"]=role
				Users["password"]=generate_password_hash(password)
				db.append(Users)
				mails.append(email)
				print(Users)
				return make_response('Employee Added Successfully.', 201)
			else:
				# returns 202 if user already exists
				return make_response('Employee already exists. Please Log in.', 202)
		else:
			return make_response('Access Denied',401,{'WWW-Authenticate' : 'Basic realm ="Login required !!"'})
			
	else:
		return make_response('Login required!!!',401,{'WWW-Authenticate' : 'Basic realm ="Login required !!"'})
@app.route('/Employees', methods =['GET'])
def get_all_employees():
	# print(Loggedin)
	if(Loggedin):
		return make_response(jsonify({'Employee List': db}),200)
	else:
		return make_response('Login required!!!',401,{'WWW-Authenticate' : 'Basic realm ="Login required !!"'})
@app.route('/Employees/<int:id>', methods =['GET'])
def get_Employee(id):
	print(id,type(id))
	if(Loggedin):
		for i in db:
			if(i["Eid"]==id):
				# print(i)
				return make_response(jsonify({'Employee Details': i}),200)
		# return make_response({"User Doesn't Exist"},404)
		return make_response('Employee not Found',404,{'WWW-Authenticate' : 'Basic realm ="User Does Not Exist"'})
	else:
		return make_response('Login required!!!',401,{'WWW-Authenticate' : 'Basic realm ="Login required !!"'})
@app.route('/Employees/<int:id>', methods =['DELETE'])
# @token_required
def delete_Employee(id):
	if(Loggedin):
		if(isAdmin):
			for i in db:
				if(i["Eid"]==id):
					print(i["email"])
					mails.remove(i["email"])
					db.remove(i)
					return make_response(jsonify({'Employees': db}),200)
			return make_response('Employee not Found',404,{'WWW-Authenticate' : 'Basic realm ="User Does Not Exist"'})
		else:
			print("1")
			return make_response('Access Denied',401,{'WWW-Authenticate' : 'Basic realm ="Login required !!"'})

	else:
		print("2")
		return make_response('Login required!!!',401,{'WWW-Authenticate' : 'Basic realm ="Login required !!"'})
@app.route('/Employees/<int:id>', methods =['PUT'])
# @token_required
def update_User(id):
	if(Loggedin):
		if(isAdmin):
			data = json.loads(request.data)
			updts=list(data)
			print(updts)
			for i in db:
				if(i["Eid"]==id):
					for j in updts:
						if(j=="email"):
							mails.remove(i["email"])
							mail=data.get("email")
							mails.append(mail)
						i[j]=data.get(j)
					return make_response(jsonify({'Employee Details': i}),200)
			return make_response('Employee not Found',404,{'WWW-Authenticate' : 'Basic realm ="User Does Not Exist"'})
		else:
			print("1")
			return make_response('Access Denied',401,{'WWW-Authenticate' : 'Basic realm ="Login required !!"'})
	else:
		print("2")
		return make_response('Login required!!!',401,{'WWW-Authenticate' : 'Basic realm ="Login required !!"'})	

	
		
if __name__ == "__main__":
    app.run()
