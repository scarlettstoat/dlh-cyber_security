Hello, Readme file here. Hopefully, I'll grow bigger and bigger with each task completed [insert smiley]

For CTF: Encoding Failures

After connecting to the VPN, head over to the target website http://web0x01.hbtn/a2/crypto_encoding_failure/login

On the login page, right-click and select Inspect. As hinted at by the task, I examined the headers in the XHR tab. I noticed a suspicious item under "Authorization" - which was further confirmed by the hint on the page itself. 

I decoded it with base64 with this script: echo -n eyd1c2VybmFtZSc6ICd5b3NyaScsICdwYXNzd29yZF9oYXNoJzogJ0R6NThOaTRQT3hGckttOFlDRGx5TGlzOGF5c1JHQkVtSGc9PSd9 | base64 -d

# {'username': 'yosri', 'password_hash': 'Dz58Ni4POxFrKm8YCDlyLis8aysRGBEmHg=='}

Then, thereafter it was straightforward. Using the script we wrote earlier, I decoded the hash to find the password.

./1-xor_decoder.sh Dz58Ni4POxFrKm8YCDlyLis8aysRGBEmHg==
# Pa#iqPdN4u0GWf-qtc4tNGNyA

Now that we have both the user name and password, I logged these details into the login page (after clicking logout first) and tried to sign in. The flag appeared. 

Crypto Cracked!
FLAG:8a9fffecb7a5f331ce46b38488992eeb

I know we could have used curl but I was running against the clock. 
