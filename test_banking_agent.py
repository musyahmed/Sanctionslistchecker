import sys
import os

# Adjust path to import from the parent directory if tests are in a subdirectory
# For this environment, assuming the test file is at the same level as the agent script or the path is handled.

from unittest.mock import MagicMock, patch

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

# from unittest.mock import MagicMock, patch # This was a duplicate line

# Test data

# Test data
USER_ID_VALID1 = "user123"
USER_ID_VALID2 = "user456"
USER_ID_INVALID = "nonexistentuser"
DUMMY_LLM_RESPONSE = "This is a mock LLM response."

def test_get_user_data_from_mock_db():
    print("Running test_get_user_data_from_mock_db...")
    passed = True
    try:
        # Test with valid user ID 1
        details1 = agent.get_user_data_from_vector_db(USER_ID_VALID1, None) # db_client is None for mock
        assert details1, f"Data for {USER_ID_VALID1} should not be empty"
        assert "name" in details1, f"'name' key missing for {USER_ID_VALID1}"
        assert "current_balance" in details1, f"'current_balance' key missing for {USER_ID_VALID1}"
        print(f"SUCCESS: Valid user {USER_ID_VALID1} data retrieved.")

        # Test with valid user ID 2
        details2 = agent.get_user_data_from_vector_db(USER_ID_VALID2, None)
        assert details2, f"Data for {USER_ID_VALID2} should not be empty"
        assert "name" in details2, f"'name' key missing for {USER_ID_VALID2}"
        assert "account_type" in details2, f"'account_type' key missing for {USER_ID_VALID2}"
        print(f"SUCCESS: Valid user {USER_ID_VALID2} data retrieved.")

        # Test with invalid user ID
        details_invalid = agent.get_user_data_from_vector_db(USER_ID_INVALID, None)
        assert not details_invalid, f"Data for {USER_ID_INVALID} should be empty"
        print(f"SUCCESS: Invalid user {USER_ID_INVALID} handled correctly.")

    except AssertionError as e:
        print(f"FAILED: test_get_user_data_from_mock_db - {e}")
        passed = False
    
    if passed:
        print("test_get_user_data_from_mock_db PASSED")
    else:
        print("test_get_user_data_from_mock_db FAILED")
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
            # 3. Fetch details for a valid user
            user_details = agent.mock_vector_db_data.get(USER_ID_VALID1)
            assert user_details, f"Could not get details for {USER_ID_VALID1} from mock_vector_db_data"
            user_name = user_details.get("name")
            
            # 4. Call ask_llm
            history = [("Hi", "Hello Morgan J. Reynolds")]
            query = "What is my current balance?"
            
            response = agent.ask_llm(history, query, user_name, user_details)
            
            # 5. Assertions
            mock_create_method.assert_called_once() # Check if chat.completions.create was called
            print("SUCCESS: OpenAI client's create method was called.")

            # Check system prompt content
            args, kwargs = mock_create_method.call_args
            messages = kwargs.get("messages", [])
            assert messages, "Messages were not passed to the LLM create method"
            
            system_prompt_found = False
            for msg in messages:
                if msg.get("role") == "system":
                    system_prompt_content = msg.get("content", "")
                    assert user_name in system_prompt_content, f"User name '{user_name}' not in system prompt: '{system_prompt_content}'"
                    assert user_details.get("account_type") in system_prompt_content, \
                        f"Account type '{user_details.get('account_type')}' not in system prompt: '{system_prompt_content}'"
                    print(f"SUCCESS: System prompt correctly contains user name and account type.")
                    system_prompt_found = True
                    break
            assert system_prompt_found, "System prompt not found in messages."

            assert response == DUMMY_LLM_RESPONSE, \
                f"Response '{response}' does not match expected dummy response '{DUMMY_LLM_RESPONSE}'"
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
    results = []
    results.append(test_get_user_data_from_mock_db())
    results.append(test_ask_llm_with_mock_data())
    
    print("\n----- Test Summary -----")
    if all(results):
        print("All tests PASSED!")
    else:
        failed_count = sum(1 for r in results if not r)
        print(f"{failed_count} test(s) FAILED.")
    print("Banking agent tests finished.")
