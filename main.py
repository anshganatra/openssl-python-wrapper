import os

def generateHash():

    algos = ['-sha256','-md5', '-sha1', '-sha224', '-sha256', '-sha384', '-sha512', '-sha3-224', '-sha3-256', '-sha3-384', '-sha3-512']
    for i in range(len(algos)):
        print(str(i+1) + '. ' + algos[i])
    algo = int(input('Select the Algorithm to be used: '))
    fileName = input('Enter the filename (eg- apples.txt): ')
    name = fileName.split(sep='.')[0]
    extension = fileName.split(sep='.')[-1]
    cmd = f'openssl dgst -out hash-{name}{algos[algo-1]}.{extension} {algos[algo-1]} {fileName}'
    os.system(cmd)
    f = open(f'hash-{name}{algos[algo-1]}.{extension}', 'r')
    print('File Hash:\n')
    print(f.read())


def verifyHash():

    algos = ['-sha256','-md5', '-sha1', '-sha224', '-sha256', '-sha384', '-sha512', '-sha3-224', '-sha3-256', '-sha3-384', '-sha3-512']
    for i in range(len(algos)):
        print(str(i+1) + '. ' + algos[i])
    algo = int(input('Select the Algorithm to be used: '))
    fileName = input('Enter the filename to verify hash of (eg- apples.txt): ')
    inputHashFile = input('Enter Hashfile to verify (eg. hash-apples-sha3-512.txt): ')
    name = fileName.split(sep='.')[0]
    extension = fileName.split(sep='.')[-1]
    cmd = f'openssl dgst -out hash-{name}{algos[algo-1]}.{extension} {algos[algo-1]} {fileName}'
    os.system(cmd)
    f = open(f'hash-{name}{algos[algo-1]}.{extension}', 'r')
    if f.read() == open(inputHashFile, 'r').read():
        print('Hash Verification Success')
    else:
        print('Invalid Hash')


def symmetricEncryption():

    algos = ['-aes-256-cbc', '-bf', '-aes-128-cbc', '-aes-128-ecb', '-aes-192-cbc', '-aes-192-ecb', '-aes-256-cbc', '-aes-256-ecb', '-des-cbc', '-des-ecb', '-des3', '-desx']
    for i in range(len(algos)):
        print(str(i+1) + '. ' + algos[i])
    algo = int(input('Select the Algorithm to be used: '))
    fileName = input('Enter the filename (eg- apples.txt): ')
    name = fileName.split(sep='.')[0]
    extension = fileName.split(sep='.')[-1]
    cmd = f'openssl enc {algos[algo-1]} -in {fileName} -out cipher-{name}{algos[algo-1]}.{extension} -base64'
    os.system(cmd)
    f = open(f'cipher-{name}{algos[algo-1]}.{extension}', 'r')
    print('Encrypted Text:\n')
    print(f.read())


def symmetricDecryption():

    algos = ['-aes-256-cbc', '-bf', '-aes-128-cbc', '-aes-128-ecb', '-aes-192-cbc', '-aes-192-ecb', '-aes-256-cbc', '-aes-256-ecb', '-des-cbc', '-des-ecb', '-des3', '-desx']
    for i in range(len(algos)):
        print(str(i+1) + '. ' + algos[i])
    algo = int(input('Select the Algorithm to be used: '))
    fileName = input('Enter the cipher filename (eg- cipher-apples-bf.txt): ')
    name = fileName.split(sep='.')[0]
    extension = fileName.split(sep='.')[-1]
    cmd = f'openssl enc -d {algos[algo-1]} -in {fileName} -out plain-{name}{algos[algo-1]}.{extension} -base64'
    os.system(cmd)
    f = open(f'plain-{name}{algos[algo-1]}.{extension}', 'r')
    print('Decrypted Text:\n')
    print(f.read())


def rsaKeypair():

    os.system('openssl genrsa -out rsaprivatekey.pem 2048')
    os.system('openssl rsa -in rsaprivatekey.pem -pubout -out rsapublickey.pem')
    f = open('rsaprivatekey.pem', 'r')
    print(f.read())
    print('\n')
    f = open('rsapublickey.pem', 'r')
    print(f.read())


def generateDigitalSignature():

    fileName = input('Enter the filename to sign (eg- apples.txt): ')
    name = fileName.split(sep='.')[0]
    # extension = fileName.split(sep='.')[-1]
    pvtKey = input('Enter Private Key filename (eg. privatekey.pem): ')
    os.system(f'openssl dgst -sha256 -sign {pvtKey} -out sign.sha256 {fileName}')
    os.system(f'openssl enc -base64 -in sign.sha256 -out {name}-signature.txt')
    os.remove('sign.sha256')
    print(f'Digital Signature Created: {name}-signature.txt')


def verifyDigitalSignature():

    fileName = input('Enter the filename to verify sign (eg. apples.txt): ')
    name = fileName.split(sep='.')[0]
    # extension = fileName.split(sep='.')[-1]
    publicKey = input('Enter Public Key filename (eg. publickey.pem): ')
    sign = input('Enter Signature filename: ')
    os.system(f'openssl enc -base64 -d -in {sign} -out sign.sha256')
    os.system(f'openssl dgst -sha256 -verify {publicKey} -signature sign.sha256 {fileName}')
    os.remove('sign.sha256')


def generateSSL():

    print('Enter the following details. Leave empty to use default values.')
    country = input('Country Name: ').strip()
    state = input('State or Province Name: ').strip()
    locality = input('Locality Name: ').strip()
    organisationName = input('Organisation Name: ').strip()
    organisationUnitName = input('Organisational Unit Name: ').strip()
    commonName = input('Common Name: ').strip()
    email = input('Email Address: ').strip()

    country = country if country != '' else 'IN'
    state = state if state != '' else 'MH'
    locality = locality if locality != '' else 'Mumbai'
    organisationName = organisationName if organisationName != '' else 'BEST'
    organisationUnitName = organisationUnitName if organisationUnitName != '' else 'Electricity'
    commonName = commonName if commonName != '' else 'bestbmc.com'
    email = email if email != '' else 'contact@bestbmc.com'

    cmd = 'openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -subj ' + f'/C={country}/ST={state}/L={locality}/O={organisationName}/OU={organisationUnitName}/CN={commonName}/emailAddress={email}'
    disp = 'openssl x509 -in cert.pem -noout -text'
    
    os.system(cmd)
    os.system(disp)













while(True):
    choice = int(input('\n'+'-'*50+'\nSelect from the following:\n1. Generate Hash \n2. Symmetric Encryption\n3. RSA Keypair Generation\n4. Digital Signature\n5. Generate SSL Certificate\nCHOICE: '))
    if choice == 1:
        option = int(input('\n1. Generate\n2. Verify\nSelect your option: '))
        if option == 1:
            generateHash()
        else:
            verifyHash()
    elif choice == 2:
        option = int(input('\n1. Encrypt\n2. Decrypt\nSelect your option: '))
        if option == 1:
            symmetricEncryption()
        else:
            symmetricDecryption()
    elif choice == 3:
        rsaKeypair()
    elif choice == 4:
        option = int(input('\n1. Generate\n2. Verify\nSelect your option: '))
        if option == 1:
            generateDigitalSignature()
        else:
            verifyDigitalSignature()
    else:
        generateSSL()

