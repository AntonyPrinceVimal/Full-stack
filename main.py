import firebase_admin
from firebase_admin import credentials, firestore
from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from jose import jwt
from datetime import datetime, timedelta
import os
from dotenv import load_dotenv

load_dotenv()

SECRET_KEY=os.getenv("secret_key")
ALGORITHM=os.getenv("algorithm")
TOKEN_EXPIRE=datetime(2030,1,1)

def createToken(a):
  payload={
    "sub":a,
    "iat":datetime.utcnow(),
    "exp":TOKEN_EXPIRE
  }
  token=jwt.encode(payload,SECRET_KEY,algorithm=ALGORITHM)
  return token

def decode(a):
  payload=jwt.decode(a,SECRET_KEY,algorithms=[ALGORITHM])
  docId=payload.get("sub")
  return docId

app=FastAPI()

app.add_middleware(
  CORSMiddleware,
  allow_origins=["https://sammytester.netlify.app",],
  allow_credentials=True, 
  allow_methods=["*"], 
  allow_headers=["*"],
  expose_headers=["Set-Cookie"] 
)

firebase_creds = {
  "type": os.getenv("FIREBASE_TYPE"),
  "project_id": os.getenv("FIREBASE_PROJECT_ID"),
  "private_key_id": os.getenv("FIREBASE_PRIVATE_KEY_ID"),
  "private_key": os.getenv("FIREBASE_PRIVATE_KEY").replace("\\n", "\n"), 
  "client_email": os.getenv("FIREBASE_CLIENT_EMAIL"),
  "client_id": os.getenv("FIREBASE_CLIENT_ID"),
  "auth_uri": os.getenv("FIREBASE_AUTH_URI"),
  "token_uri": os.getenv("FIREBASE_TOKEN_URI"),
  "auth_provider_x509_cert_url": os.getenv("FIREBASE_AUTH_PROVIDER_X509_CERT_URL"),
  "client_x509_cert_url": os.getenv("FIREBASE_CLIENT_X509_CERT_URL"),
  "universe_domain":os.getenv("UNIVERSE_DOMAIN")
}
cred=credentials.Certificate(firebase_creds)
firebase_admin.initialize_app(cred)
db=firestore.client()


class signup(BaseModel):
  userName:str
  password:str

class login(BaseModel):
  userName:str
  password:str
  
class Format(BaseModel):
  name:str
  price:str
  detail:str
  image:str

class Document(BaseModel):
  docId:str
  
@app.get("/checking")
async def checking(request: Request):
  cookie=request.cookies.get("token")
  if cookie:
    return "yes"
  else:
    return "no"


@app.post("/signup")
async def signup(res:Response, sign:signup):
  collection=db.collection("UserDemo")
  doc=collection.where("userName", "==", sign.userName)
  new=doc.stream()
  if any(new):
    return " User already exist"

  else:
    currentTime=datetime.utcnow()
    data={
      "userName":sign.userName,
      "password":sign.password,
      "createdAt":currentTime,
      " myPurchase":[]
    }
    user=collection.add(data)
    userId=user[1].id
    tokenn=createToken(userId)
    res.set_cookie (key="token", value=tokenn, httponly=True, samesite="None",secure=True, max_age=3600000000000000000)
    return "success"

@app.post("/login")
async def login(res:Response, log:login):
  collection=db.collection("UserDemo")
  doc=collection.where("userName", "==", log.userName).where("password","==",log.password)
  existData=doc.stream()
  finalData=list(existData)
  if finalData:
    docId=" banana"
    for doc in finalData:
      docId=doc.id

    tokenn=createToken(docId)
    res.set_cookie(key="token", value=tokenn, httponly=True, samesite="None",secure=True, max_age=3600000000000000000)
    return "logged and setted cookie"
  else:
    return "invalid username or password"


@app.get("/homePage")
async def homePage():
  emptyList=[]
  collection=db.collection("ProductDemo")
  allDocs=collection.stream()
  for a in allDocs:
    emptyList.append({"id":a.id,**a.to_dict()})
  return emptyList
  
@app.post("/addProduct")
async def addProduct(format:Format, req:Request):
  currentTime=datetime.utcnow()
  cookie=req.cookies.get("token")
  if not cookie:
    return "no cookie"
  docId=decode(cookie)
  collection=db.collection("ProductDemo")
  data={
    "productName":format.name,
    "price":format.price,
    "detail":format.detail,
    "image":format.image,
    "createdAt":currentTime,
    "owner":docId,
    "sales":0
    
  }
  collection.add(data)
  return "product uploaded successfully"

@app.get("/myProduct")
async def myProduct(req:Request):
  cookie=req.cookies.get("token")
  if not cookie:
    return "error"
  docId=decode(cookie)
  if not docId:
    return "errorr"
  emptyList=[]
  collection=db.collection("ProductDemo")
  query=collection.where("owner","==",docId)
  streaming=query.stream()
  for a in streaming:
    emptyList.append({"id":a.id,**a.to_dict()})
  return emptyList

@app.get("/checkCookies")
async def checkCookies(req: Request):
    cookie = req.cookies.get("token")
    if cookie:
        return {"message": "Cookies exist!"}
    return {"message": "No cookies found"}

@app.post("/myPurchase")
async def myPurchase (doc:Document, req:Request):
  cookie=req.cookies.get("token")
  userId=decode(cookie)
  collection=db.collection("UserDemo")
  docc=collection.document(userId)
  docc.update({
    "myPurchase":firestore.ArrayUnion([doc.docId])
  })
  productCollection=db.collection("ProductDemo")
  productDoc=productCollection.document(doc.docId)
  productDoc.update({
    "sales":firestore.Increment(1)
  })
  return "added increment and myPurchase"
