from google.cloud import kms
import base64
import crcmod
import six


def create_key_ring(project_id, location_id, id, client):
    
    location_name = f'projects/{project_id}/locations/{location_id}'
    key_ring = {}
    created_key_ring = client.create_key_ring(request={'parent': location_name, 'key_ring_id': id, 'key_ring': key_ring})
    print('Created key ring: {}'.format(created_key_ring.name))
    return created_key_ring


def create_key_hsm(project_id, location_id, key_ring_id, id, client):
    
    key_ring_name = client.key_ring_path(project_id, location_id, key_ring_id)
    purpose = kms.CryptoKey.CryptoKeyPurpose.ENCRYPT_DECRYPT
    algorithm = kms.CryptoKeyVersion.CryptoKeyVersionAlgorithm.GOOGLE_SYMMETRIC_ENCRYPTION
    protection_level = kms.ProtectionLevel.HSM
    key = {
        'purpose': purpose,
        'version_template': {
            'algorithm': algorithm,
            'protection_level': protection_level
        }
    }
    created_key = client.create_crypto_key(request={'parent': key_ring_name, 'crypto_key_id': id, 'crypto_key': key})
    print('Created hsm key: {}'.format(created_key.name))
    return created_key


def encrypt_symmetric(project_id, location_id, key_ring_id, key_id, plaintext, client):

    plaintext_bytes = plaintext.encode('utf-8')
    plaintext_crc32c = crc32c(plaintext_bytes)
    key_name = client.crypto_key_path(project_id, location_id, key_ring_id, key_id)
    encrypt_response = client.encrypt(
      request={'name': key_name, 'plaintext': plaintext_bytes, 'plaintext_crc32c': plaintext_crc32c})
    if not encrypt_response.verified_plaintext_crc32c:
        raise Exception('The request sent to the server was corrupted in-transit.')
    if not encrypt_response.ciphertext_crc32c == crc32c(encrypt_response.ciphertext):
        raise Exception('The response received from the server was corrupted in-transit.')
    print('Ciphertext: {}'.format(base64.b64encode(encrypt_response.ciphertext)))
    return encrypt_response


def crc32c(data):
    
    crc32c_fun = crcmod.predefined.mkPredefinedCrcFun('crc-32c')
    return crc32c_fun(six.ensure_binary(data))


def decrypt_symmetric(project_id, location_id, key_ring_id, key_id, ciphertext, client):
    
    key_name = client.crypto_key_path(project_id, location_id, key_ring_id, key_id)
    decrypt_response = client.decrypt(request={'name': key_name, 'ciphertext': ciphertext})
    print('Plaintext: {}'.format(decrypt_response.plaintext))
    return decrypt_response



if __name__ == '__main__':

    project_id = input("enter project id: ")
    location_id = input("enter location id: ")
    id = input("enter id: ")
    print("what do you want: ")
    print("1 - Create Key Ring")
    print("2 - Create Key HSM")
    print("3 - Encrypt")
    print("4 - Decrypt")
    answer = input(": ")
    client = kms.KeyManagementServiceClient()

    if answer == "1":
        created_key_ring = create_key_ring(project_id, location_id, id, client)
        print("Key ring", created_key_ring)

    if answer == "2":
        key_ring_id = input("enter key ring id: ")
        key_id = create_key_hsm(project_id, location_id, key_ring_id, id, client)
        print(key_id)
    
    if answer == "3":
        key_ring_id = input("enter key ring id: ")
        key_id = input("enter key id: ")
        plaintext = input("enter plaintext: ")
        enc = encrypt_symmetric(project_id, location_id, key_ring_id, key_id, plaintext, client)
        print(enc)

    if answer == "4":
        key_ring_id = input("enter key ring id: ")
        key_id = input("enter key id: ")
        ciphertext = input("enter ciphertext: ")
        dec = decrypt_symmetric(project_id, location_id, key_ring_id, key_id, ciphertext, client)
        print(dec)