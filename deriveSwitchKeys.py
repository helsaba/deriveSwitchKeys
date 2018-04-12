# Derive Switch Keys [PK21, Title, App, Ocean, Sys]
# SocraticBliss [Mastarifla]
# Copyright 2018 All rights reserved
# Feel free to submit code changes/optimizations/updates

from binascii import unhexlify as uhx, hexlify as hx
from Crypto.Cipher import AES
import sys

master_keys = ['XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX',
               'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX',
               'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX',
               'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX']
               
package2_key_source = 'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX'
titlekek_source = 'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX'
aes_kek_generation_source = 'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX'
aes_key_generation_source = 'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX'
key_area_application_source = 'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX'
key_area_key_ocean_source = 'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX'
key_area_key_system_source = 'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX'
  
def decrypt(keyName, isKek, sourceKey):
    for key in range(len(master_keys)):
        # Create the MasterKey Cipher
        masterKey_cipher = AES.new(uhx(master_keys[key]), AES.MODE_ECB)

        if isKek:
            # Decrypt the Kek Gen Source
            dec_kekGenSource = masterKey_cipher.decrypt(uhx(aes_kek_generation_source))
            # Create the Kek Cipher
            kek_cipher = AES.new(uhx(hx(dec_kekGenSource).upper()), AES.MODE_ECB)
            # Use the Kek Cipher to Decrypt the Source Key
            dec_keyAreaKey = kek_cipher.decrypt(uhx(sourceKey))
            # Create the Key Cipher
            key_cipher = AES.new(uhx(hx(dec_keyAreaKey).upper()), AES.MODE_ECB)
            # Use the Key Cipher to Decrypt the Key Gen Source
            dec_sourceKey = key_cipher.decrypt(uhx(aes_key_generation_source))
            
        else:
            # Use the MasterKey Cipher to Decrypt the Source Key
            dec_sourceKey = masterKey_cipher.decrypt(uhx(sourceKey))
        
        # Print out the Generated Keys [MasterKey Enumerated]
        print('%s%d = %s' % (keyName, key, hx(dec_sourceKey).upper()))

def main():
    try:
        decrypt('package2_key_0', False, package2_key_source)
        decrypt('titlekek_0', False, titlekek_source)
        decrypt('key_area_key_application_0', True, key_area_application_source)
        decrypt('key_area_key_ocean_0', True, key_area_key_ocean_source)
        decrypt('key_area_key_system_0', True, key_area_key_system_source)
    
    except TypeError:
        print('You forgot to add your prerequisite keys to the script...')

if __name__ == '__main__':
    sys.exit(main())
