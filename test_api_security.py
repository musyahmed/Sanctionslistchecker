import unittest # Using unittest for structure, can be adapted to pytest
from fastapi.testclient import TestClient
import pyotp
import time # For rate limit testing

from unittest.mock import patch, call # Ensure 'call' is imported if needed for history assertion

# Import the FastAPI app and other necessary components from main_api
# Ensure main_api.py can be imported (e.g., it's in PYTHONPATH or same directory)
# The main_api.py already handles dummy OPENAI_API_KEY and mocks Google TTS for import.
try:
    import main_api # Import the module itself
    from main_api import app, UserInDB # Import specific classes if needed directly
except ImportError as e:
    print(f"Failed to import from main_api: {e}")
    print("Ensure main_api.py is accessible and all its internal imports are resolved.")
    raise

client = TestClient(app)

# Helper to reset state for test isolation
# This will now be handled by the setUp method of the TestCase
# def reset_global_state():
#     """Resets mock_user_db, blocklist_client, and conversation_history_client for test isolation."""
#     main_api.mock_user_db.clear()
#     main_api.blocklist_client = main_api.RedisClientPlaceholder()
#     main_api.conversation_history_client = main_api.DynamoDBClientPlaceholder()
#     print("Global state reset.")


class TestAPISecurity(unittest.TestCase):

    def setUp(self):
        """Reset state before each test method."""
        main_api.mock_user_db.clear()
        main_api.blocklist_client = main_api.RedisClientPlaceholder()
        main_api.conversation_history_client = main_api.DynamoDBClientPlaceholder()
        # print("Global state (mock_user_db, blocklist_client, conversation_history_client) reset via setUp.")


    # --- 1. Authentication Tests (JWT) ---
    def test_register_and_login(self):
        print("\nRunning test_register_and_login...")
        # self.setUp() handles global state reset
        # Register
        reg_response = client.post("/register", json={"username": "testuser1", "password": "testpassword123"})
        self.assertEqual(reg_response.status_code, 200)
        self.assertEqual(reg_response.json()["username"], "testuser1")
        print("User registration successful.")

        # Login
        login_response = client.post("/login", data={"username": "testuser1", "password": "testpassword123"})
        self.assertEqual(login_response.status_code, 200)
        self.assertIn("access_token", login_response.json())
        self.assertEqual(login_response.json()["token_type"], "bearer")
        print("User login successful, token received.")

    def test_access_protected_endpoint_no_token(self):
        print("\nRunning test_access_protected_endpoint_no_token...")
        # self.setUp() handles global state reset
        # For /mfa/setup, no such data dependency, just auth.
        response = client.post("/mfa/setup")
        self.assertIn(response.status_code, [401, 403]) # FastAPI default is 401 for Depends(oauth2_scheme)
        print(f"/mfa/setup without token failed with {response.status_code} as expected.")

    def test_access_protected_endpoint_invalid_token(self):
        print("\nRunning test_access_protected_endpoint_invalid_token...")
        # self.setUp() handles global state reset
        headers = {"Authorization": "Bearer invalidtoken123"}
        response = client.post("/mfa/setup", headers=headers)
        self.assertIn(response.status_code, [401, 403])
        print(f"/mfa/setup with invalid token failed with {response.status_code} as expected.")

    def test_logout_and_token_revocation(self):
        print("\nRunning test_logout_and_token_revocation...")
        # self.setUp() handles global state reset
        # Register and Login
        client.post("/register", json={"username": "logoutuser", "password": "password123"})
        login_resp = client.post("/login", data={"username": "logoutuser", "password": "password123"})
        self.assertEqual(login_resp.status_code, 200)
        token = login_resp.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}
        print("User logged in for logout test.")

        # Access a protected endpoint to confirm token works
        # Using /mfa/setup as it's simple and protected
        mfa_setup_resp_before_logout = client.post("/mfa/setup", headers=headers)
        self.assertEqual(mfa_setup_resp_before_logout.status_code, 200)
        print("Protected endpoint /mfa/setup accessed successfully before logout.")

        # Logout
        logout_resp = client.post("/logout", headers=headers)
        self.assertEqual(logout_resp.status_code, 200)
        self.assertEqual(logout_resp.json()["message"], "Successfully logged out")
        print("Logout successful.")
        # Access the internal _blocklist of the placeholder for assertion
        self.assertGreater(len(main_api.blocklist_client._blocklist), 0, "Token JTI should be in blocklist after logout")

        # Attempt to use the same token again
        mfa_setup_resp_after_logout = client.post("/mfa/setup", headers=headers)
        self.assertIn(mfa_setup_resp_after_logout.status_code, [401, 403])
        print(f"Protected endpoint /mfa/setup access denied with {mfa_setup_resp_after_logout.status_code} after logout as expected.")

    # --- 2. Input Validation Tests ---
    def test_register_input_validation(self):
        print("\nRunning test_register_input_validation...")
        # self.setUp() handles global state reset
        # Short username
        response_short_user = client.post("/register", json={"username": "us", "password": "password123"})
        self.assertEqual(response_short_user.status_code, 422)
        print("Registration with short username failed with 422 as expected.")

        # Short password
        response_short_pass = client.post("/register", json={"username": "validuser", "password": "pass"})
        self.assertEqual(response_short_pass.status_code, 422)
        print("Registration with short password failed with 422 as expected.")

        # Missing fields (FastAPI/Pydantic handles this automatically)
        response_missing_pass = client.post("/register", json={"username": "anotheruser"})
        self.assertEqual(response_missing_pass.status_code, 422)
        print("Registration with missing password failed with 422 as expected.")

    @patch('main_api.agent_module.ask_llm') # Mock ask_llm for this test
    def test_chat_input_validation(self, mock_ask_llm):
        print("\nRunning test_chat_input_validation...")
        # self.setUp() called automatically by unittest runner
        mock_ask_llm.return_value = "Dummy LLM response for validation test."

        # Register and login to get a token.
        # User 'user123' is one of the users the placeholder VectorDBClient returns data for.
        chat_user = "user123"
        client.post("/register", json={"username": chat_user, "password": "password123"})
        login_resp = client.post("/login", data={"username": chat_user, "password": "password123"})
        token = login_resp.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}
        print(f"User '{chat_user}' logged in for chat validation test.")

        # Empty query
        response_empty_q = client.post("/chat", headers=headers, json={"query": ""})
        self.assertEqual(response_empty_q.status_code, 422)
        print("Chat with empty query failed with 422 as expected.")

        # Query too long (max_length=1000)
        long_query = "a" * 1001
        response_long_q = client.post("/chat", headers=headers, json={"query": long_query})
        self.assertEqual(response_long_q.status_code, 422)
        print("Chat with too long query failed with 422 as expected.")

        # Query with disallowed characters (pattern=r"^[a-zA-Z0-9\s.,?!'-]+$")
        invalid_char_query = "Hello <script>alert('XSS')</script>" # Contains < >
        response_invalid_char_q = client.post("/chat", headers=headers, json={"query": invalid_char_query})
        self.assertEqual(response_invalid_char_q.status_code, 422)
        print("Chat with disallowed characters failed with 422 as expected.")

        # Valid query
        valid_query = "What is my balance?"
        response_valid_q = client.post("/chat", headers=headers, json={"query": valid_query})
        self.assertEqual(response_valid_q.status_code, 200) # Validation passes, mock LLM responds
        print("Chat with valid query passed Pydantic validation (status 200).")


    # --- 3. Rate Limiting Tests (Conceptual/Basic) ---
    def test_rate_limit_login_endpoint(self):
        print("\nRunning test_rate_limit_login_endpoint...")
        # self.setUp() handles global state reset
        # Note: This test's reliability depends on slowapi's in-memory storage behavior across test runs.
        # It might pass once and then fail on subsequent immediate runs if the state isn't perfectly isolated
        # or if time doesn't 'move' for the limiter. For this subtask, structure is key.
        # The limit for /login is "10/minute"

        # Register a user for login attempts
        client.post("/register", json={"username": "ratelimituser", "password": "password123"})
        print("User 'ratelimituser' registered for rate limit test.")

        successful_attempts = 0
        failed_attempts = 0

        for i in range(15): # Attempt 15 times
            response = client.post("/login", data={"username": "ratelimituser", "password": "password123"})
            if response.status_code == 200:
                successful_attempts += 1
            elif response.status_code == 429:
                failed_attempts += 1
                print(f"Attempt {i+1}: Received 429 Too Many Requests as expected.")
            else:
                # Other unexpected errors
                self.fail(f"Attempt {i+1}: Unexpected status code {response.status_code} - {response.text}")

            if failed_attempts > 0: # Stop if we start getting rate limited
                break
            # time.sleep(0.1) # Small delay, might not be effective for 'per minute' limits without longer waits

        self.assertLessEqual(successful_attempts, 10, "Should not allow more than 10 successful attempts within the window.")
        self.assertGreater(failed_attempts, 0, "Should have hit rate limit and received 429.")
        print(f"Rate limit test for /login: {successful_attempts} successful, {failed_attempts} rate-limited. Test passed.")


    # --- 4. MFA Flow Tests (Basic) ---
    def test_mfa_setup_and_login_flow(self):
        print("\nRunning test_mfa_setup_and_login_flow...")
        # self.setUp() handles global state reset
        mfa_user = "mfauser1"
        mfa_password = "mfapassword123"

        # Register user
        reg_response = client.post("/register", json={"username": mfa_user, "password": mfa_password})
        self.assertEqual(reg_response.status_code, 200)
        print("MFA test user registered.")

        # Login to get initial token
        login_resp1 = client.post("/login", data={"username": mfa_user, "password": mfa_password})
        self.assertEqual(login_resp1.status_code, 200)
        token1 = login_resp1.json()["access_token"]
        headers1 = {"Authorization": f"Bearer {token1}"}
        print("MFA test user logged in (MFA not yet enabled).")

        # Call /mfa/setup
        setup_resp = client.post("/mfa/setup", headers=headers1)
        self.assertEqual(setup_resp.status_code, 200)
        self.assertIn("provisioning_uri", setup_resp.json())
        mfa_secret_for_testing = setup_resp.json().get("mfa_secret_for_testing")
        self.assertIsNotNone(mfa_secret_for_testing, "MFA secret should be returned for testing.")
        print(f"MFA setup initiated. Secret (for test): {mfa_secret_for_testing}")

        # Verify the user in mock_user_db has the secret set
        self.assertIn(mfa_user, main_api.mock_user_db) # Use main_api.mock_user_db
        self.assertEqual(main_api.mock_user_db[mfa_user].mfa_secret, mfa_secret_for_testing)

        # Generate TOTP and call /mfa/verify
        totp_code_verify = pyotp.TOTP(mfa_secret_for_testing).now()
        verify_resp = client.post("/mfa/verify", headers=headers1, json={"totp_code": totp_code_verify})
        self.assertEqual(verify_resp.status_code, 200)
        self.assertEqual(verify_resp.json()["message"], "MFA enabled successfully.")
        self.assertTrue(main_api.mock_user_db[mfa_user].is_mfa_enabled) # Use main_api.mock_user_db
        print("MFA verified and enabled.")

        # Attempt /login again, should require MFA
        login_resp2 = client.post("/login", data={"username": mfa_user, "password": mfa_password})
        self.assertEqual(login_resp2.status_code, 200) # The endpoint itself returns 200 for MFA required
        self.assertTrue(login_resp2.json().get("mfa_required"))
        self.assertEqual(login_resp2.json().get("username"), mfa_user)
        print("Login attempt after MFA enable correctly indicates mfa_required.")

        # Generate new TOTP and call /login/mfa/validate
        totp_code_login = pyotp.TOTP(mfa_secret_for_testing).now()
        mfa_validate_resp = client.post("/login/mfa/validate", json={"username": mfa_user, "totp_code": totp_code_login})
        self.assertEqual(mfa_validate_resp.status_code, 200)
        self.assertIn("access_token", mfa_validate_resp.json())
        print("Login with MFA TOTP validation successful, new token received.")

if __name__ == "__main__":
    # This allows running the tests directly with `python test_api_security.py`
    # It's a simple way to run tests without a full test runner like pytest for this environment.

    # Ensure OPENAI_API_KEY is set if main_api.py's import of agent_module requires it at import time
    # main_api.py handles this by setting a dummy key if not found, for its own Uvicorn run.
    # TestClient might inherit this, or we might need to set it explicitly if tests run in a separate context.
    # For now, assuming main_api.py's import logic for agent_module handles this.

    # New test for conversation history
    @patch('main_api.agent_module.ask_llm')
    def test_chat_conversation_history(self, mock_ask_llm):
        print("\nRunning test_chat_conversation_history...")
        # self.setUp() called by unittest runner

        history_user = "historyuser"
        # Register and login
        client.post("/register", json={"username": history_user, "password": "password123"})
        login_resp = client.post("/login", data={"username": history_user, "password": "password123"})
        token = login_resp.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}
        print(f"User '{history_user}' logged in for conversation history test.")

        # First chat interaction
        query1 = "Hello, this is my first query."
        response1_llm = "Hello! This is response 1."
        mock_ask_llm.return_value = response1_llm

        chat_resp1 = client.post("/chat", headers=headers, json={"query": query1})
        self.assertEqual(chat_resp1.status_code, 200)
        self.assertEqual(chat_resp1.json()["response"], response1_llm)

        # Check that ask_llm was called with empty or default history for the first call
        # The actual user_details might be complex, so we use unittest.mock.ANY for that if needed,
        # but for history, it should be empty.
        # args, kwargs = mock_ask_llm.call_args
        # self.assertEqual(kwargs['history'], []) # Or check for specific format if it's not empty by default
        # For simplicity, let's check the number of calls first, then inspect args of the last call.
        mock_ask_llm.assert_called_once()
        call_args_first = mock_ask_llm.call_args
        self.assertEqual(call_args_first[0][0], []) # history is the first positional arg to ask_llm
        print("First chat call successful, history was empty.")

        # Second chat interaction
        query2 = "This is my second query, following up."
        response2_llm = "Understood! This is response 2, considering your first query."
        mock_ask_llm.return_value = response2_llm # Set new return value for the second call

        chat_resp2 = client.post("/chat", headers=headers, json={"query": query2})
        self.assertEqual(chat_resp2.status_code, 200)
        self.assertEqual(chat_resp2.json()["response"], response2_llm)

        # Check that ask_llm was called (total twice now)
        self.assertEqual(mock_ask_llm.call_count, 2)
        # Check that the history for the second call contained the first interaction
        call_args_second = mock_ask_llm.call_args
        expected_history_for_second_call = [(query1, response1_llm)]
        self.assertEqual(call_args_second[0][0], expected_history_for_second_call)
        print("Second chat call successful, history contained the first interaction.")

        # Verify that the conversation history client stored it
        # This is white-box testing, but useful for placeholder verification
        self.assertIn(history_user, main_api.conversation_history_client._history)
        self.assertEqual(len(main_api.conversation_history_client._history[history_user]), 2)
        self.assertEqual(main_api.conversation_history_client._history[history_user][0], (query1, response1_llm))
        self.assertEqual(main_api.conversation_history_client._history[history_user][1], (query2, response2_llm))
        print("Conversation history correctly stored in placeholder.")


if __name__ == "__main__":
    # This allows running the tests directly with `python test_api_security.py`
    print("Starting API Security Tests...")
    suite = unittest.TestSuite()
    suite.addTest(unittest.makeSuite(TestAPISecurity))

    runner = unittest.TextTestRunner()
    result = runner.run(suite)

    if result.wasSuccessful():
        print("All API security tests PASSED.")
    else:
        print(f"API security tests FAILED: {len(result.failures)} failures, {len(result.errors)} errors.")
    print("API Security Tests Finished.")
