import bcrypt

username = "rcosta"
password = "Ruben!Costa1311"

hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

# Print the output in the htpasswd format
print(f"{username}:{hashed_password}")
