from itsdangerous import URLSafeTimedSerializer
from key import secret_key
def token(email,salt):
    serializer= URLSafeTimedSerializer(secret_key)
    return serializer.dumps(email,salt=salt)
def token2(teamid,rid,salt,email=None):
    if email==None:
        serializer= URLSafeTimedSerializer(secret_key)
        return serializer.dumps({rid:teamid},salt=salt)
    else:
        return serializer.dumps({rid:[teamid,email]},salt=salt)
