from github import Github
from cryptography.hazmat.primitives import serialization as crypto_serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend as crypto_default_backend
import getpass
import os
import shutil

# Change key_title, access_token and base_url
key_title = "brenton_lin@tw-brenton"
access_token = "fdd706101c0828d825f1fe6bea1575b3a81fb9bc"
g = g = Github(base_url = "https://github.trendmicro.com/api/v3", login_or_token = access_token)
user = g.get_user()


pass_phrase = getpass.getpass("Please enter pass phrase:")
check_pass_phrase = getpass.getpass("Please enter pass phrase again:")
print(pass_phrase,"\n")

key = rsa.generate_private_key(
    backend = crypto_default_backend(),
    public_exponent = 65537,
    key_size = 2048
)

private_key = key.private_bytes(
    crypto_serialization.Encoding.PEM,
    crypto_serialization.PrivateFormat.PKCS8,
    crypto_serialization.BestAvailableEncryption(pass_phrase.encode())
).decode('utf-8')
public_key = key.public_key().public_bytes(
    crypto_serialization.Encoding.OpenSSH,
    crypto_serialization.PublicFormat.OpenSSH
).decode('utf-8')

print("private key:", private_key)
print("public key:", public_key)


for key in user.get_keys():
    if key_title in key.title:
        key.delete()
        break

user.create_key(title = key_title, key = public_key)

f = open("{}.pub".format(key_title), "w")
f.write(public_key)
f.close()
f = open("{}".format(key_title), "w")
f.write(private_key)
f.close()

ssh_path = os.path.expanduser('~/.ssh')

if os.path.exists(ssh_path):
    shutil.copyfile("{}.pub".format(key_title), "{}/{}.pub".format(ssh_path, key_title))
    shutil.copyfile("{}".format(key_title), "{}/{}".format(ssh_path, key_title))

print("\nSuccess")
