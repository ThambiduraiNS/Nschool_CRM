from cryptography.fernet import Fernet
from django.conf import settings
import base64
import os

def get_key():
    """
    Load the base64 encoded encryption key from the file specified in settings.
    Returns the decoded key as bytes.
    """
    try:
        key_file_path = settings.ENCRYPTION_KEY_FILE
        print(f"Loading key from: {key_file_path}")
        
        if not os.path.exists(key_file_path):
            raise FileNotFoundError("Encryption key file does not exist.")
        
        with open(key_file_path, 'rb') as key_file:
            encoded_key = key_file.read()
            print(f"Encoded key: {encoded_key}")  # Debugging statement

            # If the key is stored as base64, decode it
            try:
                key = base64.urlsafe_b64decode(encoded_key)
            except base64.binascii.Error as e:
                raise Exception(f"Error decoding the base64 key: {e}")

            print(f"Decoded key: {key}")  # Debugging statement
            return key

    except FileNotFoundError as e:
        raise Exception(f"Encryption key file not found: {e}")
    except IOError as e:
        raise Exception(f"Error reading the encryption key file: {e}")
    except Exception as e:
        raise Exception(f"Unexpected error: {e}")

def encrypt_password(password):
    """
    Encrypt a password using the loaded key.
    
    Args:
        password (str): The password to encrypt.
    
    Returns:
        bytes: The encrypted password.
    """
    try:
        key = get_key()
        print(f"Using key: {key}")
        print(f"Password to encrypt: {password}")

        fernet = Fernet(key)
        encrypted_password = fernet.encrypt(password.encode())
        print(f"Encrypted password: {encrypted_password}")  # Debugging statement

        return encrypted_password

    except Exception as e:
        raise Exception(f"Error encrypting password: {e}")

def decrypt_password(encrypted_password):
    """
    Decrypt a password using the loaded key.
    
    Args:
        encrypted_password (bytes): The encrypted password to decrypt.
    
    Returns:
        str: The decrypted password.
    """
    try:
        key = get_key()
        fernet = Fernet(key)

        decrypted_password = fernet.decrypt(encrypted_password).decode()
        # print(f"Decrypted password: {decrypted_password}")  # Debugging statement

        return decrypted_password

    except Exception as e:
        raise Exception(f"Error decrypting password: {e}")

encrypted_password = b'gAAAAABmsgFh-fP_Ia6kOk6Vy7PZu8qF7ujnbd55Wn6dKnG0ZMfMwpMOOxvIgiS4jX2t_yzJoN9QbazItaPzC-oQn52jFm5wqQ=='
# print(decrypt_password(encrypted_password))

def calculate_payment_totals(payments):
    totals = {
        'emi_1_total': 0,
        'emi_2_total': 0,
        'emi_3_total': 0,
        'emi_4_total': 0,
        'emi_5_total': 0,
        'emi_6_total': 0,
        'pending_amounts': {
            'emi_1_pending': 0,
            'emi_2_pending': 0,
            'emi_3_pending': 0,
            'emi_4_pending': 0,
            'emi_5_pending': 0,
            'emi_6_pending': 0
        },
        'balances': {
            'emi_1_balance': 0,
            'emi_2_balance': 0,
            'emi_3_balance': 0,
            'emi_4_balance': 0,
            'emi_5_balance': 0,
            'emi_6_balance': 0
        },
        'total_pending_amount': 0  # Initialize total_pending_amount
    }

    for payment in payments:
        print(f"Processing payment: {payment}")  # Debug: print the current payment

        for i in range(1, 7):
            emi_key = f'emi_{i}_payments'
            emi_payments = getattr(payment, emi_key, []).all()  # Get the list of EMI payments

            # Debug: Check the EMI payments
            print(f"EMI Payments for {emi_key}: {emi_payments}")

            # Sum the amounts for the current EMI, converting to float
            total_amount = 0
            for emi in emi_payments:
                if emi.amount is not None:
                    total_amount += float(emi.amount)

            # Debug: print the total amount for the current EMI
            print(f"Total amount for {emi_key}: {total_amount}")
            totals[f'emi_{i}_total'] += total_amount

            total_due = getattr(payment, f'emi_{i}_total_due', 0)  # Use getattr for safe access

            # Calculate pending amount
            pending_amount = total_due - total_amount
            totals['pending_amounts'][f'emi_{i}_pending'] += pending_amount
            totals['total_pending_amount'] += pending_amount  # Accumulate to total_pending_amount

            # Update balances
            totals['balances'][f'emi_{i}_balance'] += pending_amount

    print(f"Final totals: {totals}")  # Debug: print the final totals
    return totals





