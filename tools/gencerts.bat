openssl genrsa 2048 -out ca-key.pem
openssl req -new -x509 -nodes -days 5478 -key ca-key.pem -out ca-cert.pem

openssl req -newkey rsa:2048 -days 5478 -nodes -keyout server-key.pem -out server-req.pem
openssl x509 -req -in server-req.pem -days 5478 -CA ca-cert.pem -CAkey ca-key.pem -set_serial 01 -out server-cert.pem

openssl req -newkey rsa:2048 -days 5478 -nodes -keyout client-key.pem -out client-req.pem
openssl x509 -req -in client-req.pem -days 5478 -CA ca-cert.pem -CAkey ca-key.pem -set_serial 01 -out client-cert.pem
