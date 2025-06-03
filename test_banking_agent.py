import sys
import os

# Adjust path to import from the parent directory if tests are in a subdirectory
# For this environment, assuming the test file is at the same level as the agent script or the path is handled.

from unittest.mock import MagicMock, patch

import importlib
from cryptography.fernet import Fernet
# Assuming VectorDBClient is in real_vector_db_client.py and agent_module imports it.
# For spec in MagicMock, it's good practice to import the actual class.
from real_vector_db_client import VectorDBClient

# Attempt to mock google.cloud.texttospeech.TextToSpeechClient before agent_module is imported
# This is to prevent `DefaultCredentialsError` during import time if the agent script initializes this client globally.
mock_tts_client = MagicMock()
with patch('google.cloud.texttospeech.TextToSpeechClient', mock_tts_client):
    try:
        import agent_module as agent # Import the renamed module
    except ImportError as e:
        print(f"Error importing agent_module.py: {e}")
        print("Ensure 'agent_module.py' is in the same directory or accessible in PYTHONPATH.")
        sys.exit(1) # Exit if import fails, as tests cannot run
    except RuntimeError as e: # Catch other runtime errors during import, like missing OPENAI_API_KEY
        print(f"Runtime error during import of agent_module.py: {e}")
        sys.exit(1)


# Test data
USER_ID_VALID1 = "user123"
USER_ID_VALID2 = "user456" # Kept for potential future use, but test_get_user_data_decryption focuses on one user
USER_ID_INVALID = "nonexistentuser"
DUMMY_LLM_RESPONSE = "This is a mock LLM response."

# Store original os.environ to avoid polluting it across tests
_original_environ = None

def setUpModule():
    global _original_environ
    _original_environ = os.environ.copy()

def tearDownModule():
    if _original_environ is not None:
        os.environ.clear()
        os.environ.update(_original_environ)

def test_get_secure_encryption_key_logic():
    print("Running test_get_secure_encryption_key_logic...")
    passed = True
    original_env_key = os.environ.get("ENCRYPTION_KEY") # Store original if exists

    try:
        # Test Case 1: Key from environment variable
        print("  Testing key loading from environment variable...")
        test_env_key_bytes = Fernet.generate_key()
        test_env_key_str = test_env_key_bytes.decode()
        os.environ["ENCRYPTION_KEY"] = test_env_key_str

        with patch('builtins.print') as mock_print_env, \
             patch('google.cloud.texttospeech.TextToSpeechClient', mock_tts_client): # Added patch
            # Reload agent_module to make get_secure_encryption_key re-evaluate environment
            importlib.reload(agent)
            # Call the function that uses the key to ensure it's loaded, or directly test get_secure_encryption_key
            # For this test, we focus on get_secure_encryption_key's behavior
            loaded_key = agent.get_secure_encryption_key() # Changed agent_module to agent

        assert loaded_key == test_env_key_bytes, "Should load key from environment."
        mock_print_env.assert_any_call("INFO: Loaded encryption key from ENCRYPTION_KEY environment variable.")
        print("  SUCCESS: Key loaded from environment variable.")

        # Test Case 2: Key generation when environment variable is not set
        print("  Testing key generation when ENCRYPTION_KEY is not set...")
        if "ENCRYPTION_KEY" in os.environ:
            del os.environ["ENCRYPTION_KEY"] # Ensure it's not set

        with patch('builtins.print') as mock_print_gen, \
             patch('google.cloud.texttospeech.TextToSpeechClient', mock_tts_client): # Added patch
            importlib.reload(agent) # Reload to trigger get_secure_encryption_key again
            generated_key = agent.get_secure_encryption_key() # Changed agent_module to agent

        assert generated_key is not None and len(Fernet(generated_key).encrypt(b"test")) > 0, "Should generate a valid new key."
        mock_print_gen.assert_any_call("WARNING: ENCRYPTION_KEY environment variable not set.")
        mock_print_gen.assert_any_call("WARNING: Generating a new ephemeral encryption key for this session.")
        print("  SUCCESS: New key generated with warnings when ENCRYPTION_KEY is not set.")

    except AssertionError as e:
        print(f"  FAILED: test_get_secure_encryption_key_logic - {e}")
        passed = False
    finally:
        # Restore original ENCRYPTION_KEY state
        if original_env_key is None:
            if "ENCRYPTION_KEY" in os.environ: del os.environ["ENCRYPTION_KEY"]
        else:
            os.environ["ENCRYPTION_KEY"] = original_env_key
        # Reload agent one last time within the finally block, also needs patch
        with patch('google.cloud.texttospeech.TextToSpeechClient', mock_tts_client): # Added patch
            importlib.reload(agent) # Reload to restore original fernet instance state

    if passed:
        print("test_get_secure_encryption_key_logic PASSED")
    else:
        print("test_get_secure_encryption_key_logic FAILED")
    return passed


def test_get_user_data_decryption_with_real_client_path():
    print("Running test_get_user_data_decryption_with_real_client_path...")
    passed = True
    original_env_key = os.environ.get("ENCRYPTION_KEY")

    try:
        # 1. Setup a consistent encryption key for this test
        test_key = Fernet.generate_key()
        os.environ["ENCRYPTION_KEY"] = test_key.decode()
        with patch('google.cloud.texttospeech.TextToSpeechClient', mock_tts_client): # Added patch
            importlib.reload(agent) # Re-initialize agent_module.fernet with this key
        print(f"  INFO: Test ENCRYPTION_KEY set to: {test_key.decode()}")

        # 2. Prepare sample plaintext data and encrypt it using the reloaded agent_module's encrypt_data
        test_user_id = "user_test_decrypt"
        test_account_num_plain = "ACC12345TEST"
        test_tax_id_plain = "TAXIDTEST987"

        encrypted_acc_num = agent.encrypt_data(test_account_num_plain) # Changed agent_module to agent
        encrypted_tax_id = agent.encrypt_data(test_tax_id_plain) # Changed agent_module to agent
        print(f"  INFO: Plain Account: {test_account_num_plain} -> Encrypted: {encrypted_acc_num[:10]}...")
        print(f"  INFO: Plain Tax ID: {test_tax_id_plain} -> Encrypted: {encrypted_tax_id[:10]}...")

        # 3. Mock VectorDBClient to return this *actually* encrypted data
        mock_retrieved_data_from_db = {
            "user_id": test_user_id,
            "name": "Test Decrypt User",
            "account_number_encrypted": encrypted_acc_num,
            "tax_id_encrypted": encrypted_tax_id,
            "account_type": "savings", # Non-encrypted field
            # New contextual fields (not encrypted)
            "recent_transaction_summaries_from_db": "Sample transaction summary.",
            "relevant_faq_snippets_from_db": "Sample FAQ snippet."
        }

        mock_db_client = MagicMock(spec=VectorDBClient)
        mock_db_client.get_user_data.return_value = mock_retrieved_data_from_db

        # 4. Call get_user_data_from_vector_db with the mocked client
        retrieved_details = agent.get_user_data_from_vector_db(test_user_id, mock_db_client) # Changed agent_module to agent

        # 5. Assert decryption
        assert retrieved_details.get("account_number") == test_account_num_plain, \
            f"Decrypted account number mismatch. Expected {test_account_num_plain}, Got {retrieved_details.get('account_number')}"
        assert retrieved_details.get("tax_id") == test_tax_id_plain, \
            f"Decrypted tax_id mismatch. Expected {test_tax_id_plain}, Got {retrieved_details.get('tax_id')}"
        assert "account_number_encrypted" not in retrieved_details, "Encrypted field should be removed from final details."
        assert "tax_id_encrypted" not in retrieved_details, "Encrypted field should be removed from final details."
        # Assert that new contextual fields are present
        assert retrieved_details.get("recent_transaction_summaries_from_db") == "Sample transaction summary.", "Contextual transaction summary missing or incorrect."
        assert retrieved_details.get("relevant_faq_snippets_from_db") == "Sample FAQ snippet.", "Contextual FAQ snippet missing or incorrect."
        print("  SUCCESS: Data correctly decrypted and contextual fields retrieved.")

    except AssertionError as e:
        print(f"  FAILED: test_get_user_data_decryption_with_real_client_path - {e}")
        passed = False
    finally:
        # Clean up environment variable and reload agent_module to reset its fernet instance
        if original_env_key is None:
            if "ENCRYPTION_KEY" in os.environ: del os.environ["ENCRYPTION_KEY"]
        else:
            os.environ["ENCRYPTION_KEY"] = original_env_key
        # Reload agent one last time within the finally block, also needs patch
        with patch('google.cloud.texttospeech.TextToSpeechClient', mock_tts_client): # Added patch
            importlib.reload(agent) # Reload to restore original/default fernet state

    if passed:
        print("test_get_user_data_decryption_with_real_client_path PASSED")
    else:
        print("test_get_user_data_decryption_with_real_client_path FAILED")
    return passed


def test_ask_llm_with_mock_data():
    print("Running test_ask_llm_with_mock_data...")
    passed = True

    # 1. Setup mock for OpenAI client
    mock_openai_client = MagicMock()
    mock_chat_completions = MagicMock()
    mock_create_method = MagicMock()

    # Configure the mock 'create' method to return a dummy response structure
    dummy_choice = MagicMock()
    dummy_message = MagicMock()
    dummy_message.content = DUMMY_LLM_RESPONSE
    dummy_choice.message = dummy_message
    mock_create_method.return_value = MagicMock(choices=[dummy_choice])

    mock_chat_completions.create = mock_create_method
    mock_openai_client.chat.completions = mock_chat_completions

    try:
        # 2. Patch agent.openai_client
        with patch('agent_module.openai_client', mock_openai_client): # Patched to agent_module
            # 3. Define sample user_details including new contextual fields
            user_name = "Morgan J. Reynolds"
            sample_account_type = "Premium Checking"
            sample_transaction_summary = "Recent large deposit observed."
            sample_faq_snippet = "Information on overdraft protection available."
            sample_detailed_transactions = [
                {"date": "2025-07-15", "description": "Coffee Shop", "amount": -5.50},
                {"date": "2025-07-14", "description": "Salary Deposit", "amount": 2500.00}
            ]

            user_details_for_test = {
                "name": user_name,
                "account_type": sample_account_type,
                "recent_transaction_summaries_from_db": sample_transaction_summary,
                "relevant_faq_snippets_from_db": sample_faq_snippet,
                "detailed_transactions": sample_detailed_transactions
            }

            # 4. Call ask_llm
            history = [("Hi", "Hello Morgan J. Reynolds")] # History can be simple for this test
            query = "What is my current balance?" # Query content is less important than context handling

            response = agent.ask_llm(history, query, user_name, user_details_for_test)

            # 5. Assertions
            mock_create_method.assert_called_once()
            print("SUCCESS: OpenAI client's create method was called.")

            # Check system prompt content for new contextual information
            args, kwargs = mock_create_method.call_args
            messages = kwargs.get("messages", [])
            assert messages, "Messages were not passed to the LLM create method" # Changed

            system_prompt_found = False
            for msg in messages:
                if msg.get("role") == "system":
                    system_prompt_content = msg.get("content", "")
                    print(f"System Prompt for verification: {system_prompt_content}") # For debugging
                    assert user_name in system_prompt_content, f"User name '{user_name}' not in system prompt." # Changed
                    assert sample_account_type in system_prompt_content, "Account type not in system prompt."
                    assert sample_transaction_summary in system_prompt_content, "Transaction summary not in system prompt."
                    assert sample_faq_snippet in system_prompt_content, "FAQ snippet not in system prompt."
                    # Check for the new instruction about detailed transactions
                    assert "provide details about recent transactions from the provided transaction history" in system_prompt_content, "MFA instruction missing."
                    # Check for formatted transaction data (example from sample_detailed_transactions)
                    assert "2025-07-15 - Coffee Shop (-$5.50)" in system_prompt_content, "Formatted transaction 1 missing."
                    assert "2025-07-14 - Salary Deposit (+$2500.00)" in system_prompt_content, "Formatted transaction 2 missing."
                    assert "Use the following information to answer the user's questions:" in system_prompt_content
                    print(f"SUCCESS: System prompt correctly contains user name, all contextual details, and transaction history.")
                    system_prompt_found = True
                    break
            assert system_prompt_found, "System prompt not found in messages." # Changed

            assert response == DUMMY_LLM_RESPONSE, \
                f"Response '{response}' does not match expected dummy response '{DUMMY_LLM_RESPONSE}'" # Changed
            print(f"SUCCESS: ask_llm returned the expected dummy response.")

    except AssertionError as e:
        print(f"FAILED: test_ask_llm_with_mock_data - {e}")
        passed = False
    except Exception as e:
        print(f"ERROR: An unexpected error occurred in test_ask_llm_with_mock_data - {e}")
        passed = False

    if passed:
        print("test_ask_llm_with_mock_data PASSED")
    else:
        print("test_ask_llm_with_mock_data FAILED")
    return passed

if __name__ == "__main__":
    print("Starting banking agent tests...")
    # It's better to use unittest's built-in test discovery and execution if possible,
    # but for this script's structure, manually calling is fine.
    # Ensure setUpModule and tearDownModule are handled if not using a test runner.
    # However, since these are plain functions, we call them directly.

    setUpModule() # Manual call if not using unittest runner

    results = []
    results.append(test_get_secure_encryption_key_logic())
    results.append(test_get_user_data_decryption_with_real_client_path())
    results.append(test_ask_llm_with_mock_data())

    tearDownModule() # Manual call

    print("\n----- Test Summary -----")
    if all(results):
        print("All tests PASSED!")
    else:
        failed_count = sum(1 for r in results if not r)
        print(f"{failed_count} test(s) FAILED.")
    print("Banking agent tests finished.")
