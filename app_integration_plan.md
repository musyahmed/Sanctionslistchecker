# App Integration Plan for Personal Banking Agent

This document outlines the plan for integrating the Python-based Personal Banking Agent into a broader application ecosystem (e.g., mobile or web app).

## 1. API Definition

A RESTful API will serve as the interface between the frontend application and the backend agent logic.

*   **Suggested Framework:** **FastAPI** is recommended due to its modern features, asynchronous capabilities (suitable for I/O-bound operations like API calls and ASR), automatic data validation, and interactive API documentation (Swagger UI/OpenAPI). Flask is also a viable alternative.

*   **`/chat` Endpoint:**
    *   **Method:** `POST`
    *   **Request Body:** JSON object.
        ```json
        {
            "user_id": "string",
            "query": "string", // User's text query
            // OR, if handling direct audio upload to this endpoint:
            // "audio_file": file // (e.g., using multipart/form-data)
        }
        ```
        *Note: For audio, a separate `/transcribe` endpoint might be cleaner if complex audio processing is needed before the chat logic.*
    *   **Response Body:** JSON object.
        ```json
        {
            "response_text": "string", // The LLM's response
            "status": "string", // e.g., "success", "error"
            "error_message": "string, optional" // Details if status is "error"
        }
        ```

*   **Backend Actions for `/chat` Endpoint:**
    1.  **Authenticate Request:** Validate the incoming request using the provided authentication token (see User Authentication section).
    2.  **Retrieve User Details:** Fetch `user_details` for the given `user_id`. The `get_user_data_from_vector_db` function in `agent_module.py` now manages this. If `VECTOR_DB_URI` is set to a real URI, it uses an instance of `VectorDBClient` (currently a placeholder) to fetch data. If `VECTOR_DB_URI` is "mock_db", it returns empty data as the static mock dictionary has been removed.
    3.  **Transcribe Audio (if applicable):** If the request contains an audio file (and not pre-transcribed text), use an ASR service (like the existing `transcribe_file` function which calls OpenAI Whisper) to convert audio to text.
    4.  **Generate Query Embeddings (Future Enhancement):** Convert the text query into a vector embedding using a sentence transformer model.
    5.  **Fetch Context via Similarity Search (Future Enhancement):** Use the query embedding to search the vector database for relevant documents or transaction history snippets associated with the `user_id`. This provides context to the LLM.
    6.  **Call LLM:** Invoke the `ask_llm` function, passing the (transcribed) query, user details (including name), and any context retrieved from the vector database.
    7.  **Return Response:** Send the LLM's output back to the client in the defined JSON response format.

## 2. Data Management

The vector database (interfaced via `VectorDBClient` in `real_vector_db_client.py`) will be central to storing and retrieving user-specific information and contextual data. The `agent_module.py` initializes this client based on `VECTOR_DB_URI`. If `VECTOR_DB_URI` is set to "mock_db", no actual database is used, and the system will operate with empty user data for retrieval via `get_user_data_from_vector_db` as the internal `mock_vector_db_data` has been removed.

*   **Data Stored in Vector Database (Conceptual via `VectorDBClient`):**
    *   **User Profiles:** Core user information such as name, contact details, account types, preferences, and the `user_id` as the primary key. The `VectorDBClient` placeholder currently returns minimal mock data for specific user IDs (e.g., "user123", "user456", "user123_test_real_db") including conceptual encrypted fields and new contextual fields like `recent_transaction_summaries_from_db` and `relevant_faq_snippets_from_db`.
    *   **Embeddings of User-Specific Data:**
        *   Transaction histories: Embeddings of transaction descriptions to allow semantic search over spending patterns.
        *   User documents: If users upload any documents (e.g., for loan applications), their embeddings can be stored.
    *   **Embeddings of General Knowledge:**
        *   FAQs: Embeddings of frequently asked questions and their answers related to banking services.
        *   Product information: Details about banking products and services.
    *   **Recent Conversation History (Potential):** Short-term storage of conversation embeddings or summaries to provide better context for follow-up questions within the same session. This needs careful consideration for privacy and data lifecycle management.

*   **Data Security Considerations:**
    *   **Encryption at Rest:** All sensitive data stored in the vector database and any other persistent storage should be encrypted.
    *   **Encryption in Transit:** All data communication between the app, API backend, and database must use TLS/SSL.
    *   **Access Controls:** Strict access controls and permissions for database access.
    *   **Data Minimization:** Only store data that is essential for the agent's functionality.
    *   **Compliance:** Adhere to relevant data privacy regulations (e.g., GDPR, CCPA).

## 3. User Authentication

A robust authentication mechanism is critical to ensure secure access to user data and agent functionalities.

*   **Recommended Mechanism:** **OAuth 2.0** with **JSON Web Tokens (JWTs)**.
    *   OAuth 2.0 is a standard authorization framework.
    *   JWTs are a compact, URL-safe means of representing claims to be transferred between two parties.

*   **Authentication Flow:**
    1.  **User Login:** The user authenticates with an existing identity provider (IdP) or the bank's primary authentication system via the mobile/web app.
    2.  **Token Issuance:** Upon successful authentication, the app receives an access token (JWT) and potentially a refresh token.
    3.  **Token Transmission:** The app sends the JWT in the `Authorization` header (e.g., as a Bearer token) with every API request to the Python backend.
    4.  **Backend Token Validation:** The API backend (e.g., using middleware in FastAPI) will:
        *   Verify the JWT's signature.
        *   Check its expiration time.
        *   Validate other claims (e.g., issuer, audience) if necessary.
        *   Extract the `user_id` or other relevant identifiers from the token payload.
    5.  **Access Control:** Requests are processed only if the token is valid. The `user_id` from the token should be used for all data access operations, ensuring users can only access their own data.

*   **Implemented JWT Authentication Flow in `main_api.py`:**
    *   **Libraries Used:**
        *   `python-jose[cryptography]` for JWT creation and decoding.
        *   `passlib[bcrypt]` for password hashing and verification.
        *   FastAPI's `OAuth2PasswordBearer` for handling token retrieval from requests.
    *   **New Endpoints:**
        *   `POST /register`: Allows users to create an account by providing a username and password. Passwords are hashed using bcrypt before being stored in an in-memory mock user database (`mock_user_db`).
            *   **Input Validation:** The registration payload (`UserCreate` model) includes validation: username (min length 3, max length 50) and password (min length 8). FastAPI automatically returns a 422 error for invalid input.
        *   `POST /login`: Allows users to log in with their username and password. If credentials are valid, a JWT access token is generated and returned. This endpoint uses `OAuth2PasswordRequestForm` for standard form data login.
    *   **Token Generation:**
        *   Upon successful login, `create_access_token` function generates a JWT.
        *   The token includes a subject (`sub`) claim containing the username and an expiration time.
        *   The `SECRET_KEY` and `ALGORITHM` (HS256) are used for signing the token.
    *   **Securing `/chat` Endpoint:**
        *   The `/chat` endpoint now requires a valid JWT.
        *   A dependency function `get_current_user` verifies the token provided in the `Authorization` header.
        *   If the token is valid, the username is extracted from the token's subject. This username is then used as the `user_id` to fetch user-specific data via `get_user_data_from_vector_db` (which now uses `VectorDBClient` or returns empty for "mock_db" mode) for the agent interaction.
        *   The `ChatRequest` model no longer requires `user_id` in the request body, as it's derived from the token.
    *   **Mock User Store:** An in-memory dictionary (`mock_user_db`) is used to store registered users and their hashed passwords for demonstration purposes.

*   **Conceptual TOTP-Based Multi-Factor Authentication (MFA) Flow (using `pyotp`):**
    *   **User Model Update:** The internal user representation (`UserInDB`) is updated to include `mfa_secret: Optional[str]` and `is_mfa_enabled: bool`. New users at `/register` are initialized with MFA disabled.
    *   **MFA Setup Process:**
        *   `POST /mfa/setup` (JWT Authenticated):
            *   Generates a new TOTP secret (`pyotp.random_base32()`) for the authenticated user.
            *   Stores this secret with the user's record (e.g., in `mock_user_db`).
            *   Returns a provisioning URI (`pyotp.totp.TOTP(secret).provisioning_uri()`) for the user to scan with an authenticator app. For testing, the secret itself is also returned (this should be removed in production).
        *   `POST /mfa/verify` (JWT Authenticated):
            *   Requires a `totp_code` from the user.
            *   Verifies the provided code against the stored `mfa_secret` using `pyotp.TOTP(secret).verify(token)`.
            *   If valid, sets `is_mfa_enabled = True` for the user.
    *   **Modified Login Flow:**
        *   `POST /login`:
            *   After successful username/password verification, it checks if `is_mfa_enabled` is true for the user.
            *   If MFA is enabled, it does not return a JWT. Instead, it returns a response like `{"mfa_required": True, "username": user.username}`, indicating that a TOTP code is needed.
            *   If MFA is not enabled, it returns a JWT as usual.
        *   `POST /login/mfa/validate`:
            *   Accepts `username` and `totp_code`.
            *   Retrieves the user and verifies the `totp_code` against their stored `mfa_secret`.
            *   If valid, a JWT is generated and returned, completing the login.
            *   If invalid, an authentication error is returned.
    *   **Libraries:** The `pyotp` library is used for generating secrets and verifying TOTP codes.

*   **Session Management and JWT Revocation:**
    *   **JWT Expiration:** JWTs are configured to expire after a set duration (`ACCESS_TOKEN_EXPIRE_MINUTES` in `main_api.py`), which is the primary mechanism for session timeout.
    *   **JWT ID (`jti`) Claim:** Each JWT generated by `create_access_token` now includes a unique `jti` (JWT ID) claim, generated using `uuid.uuid4()`.
    *   **Token Blocklist (Conceptual Persistent Store via `RedisClientPlaceholder`):**
        *   The in-memory Python `set` (`token_blocklist`) has been replaced with an instance of `RedisClientPlaceholder` named `blocklist_client`.
        *   This `RedisClientPlaceholder` class (defined in `main_api.py`) simulates the interface of a Redis client, using an internal Python `set` for demonstration.
        *   The `TokenData` Pydantic model includes the `jti`.
    *   **Logout Endpoint (`POST /logout`):**
        *   This endpoint is JWT authenticated.
        *   Upon successful request, it extracts the `jti` from the current user's validated token data.
        *   The extracted `jti` is added to the `blocklist_client` using `blocklist_client.add(jti, expires_in_seconds)`. The `expires_in_seconds` parameter is set to match the JWT's original validity period, conceptually mimicking Redis's `SETEX` command.
    *   **Token Validation Update (`get_current_user_data`):**
        *   The `get_current_user_data` dependency function now checks for the `jti` in the `blocklist_client` using `blocklist_client.contains(jti)`.
        *   It continues to extract the `jti` claim and raises exceptions if it's missing or found in the blocklist.
    *   **Production Note:** For a production environment, the `RedisClientPlaceholder` **must be replaced** with a real, robust client (e.g., `redis-py`) connected to a persistent and shared Redis instance (or similar like Memcached) for the token blocklist. This ensures the blocklist is effective across multiple API instances and survives server restarts.

## 4. Deployment

Considerations for hosting the API backend and the vector database.

*   **Python API Backend Hosting Options:**
    *   **Serverless Functions:**
        *   AWS Lambda: Cost-effective for event-driven, scalable workloads. API Gateway can be used to expose the HTTP endpoint.
        *   Google Cloud Functions: Similar to AWS Lambda, offering scalability and pay-per-use.
        *   *Pros:* Scalability, reduced operational overhead. *Cons:* Potential for cold starts, limitations on execution time for complex tasks (though usually sufficient for this use case).
    *   **Containerization (Docker):**
        *   AWS Elastic Container Service (ECS) or AWS Fargate: Managed container orchestration.
        *   Google Kubernetes Engine (GKE) or Google Cloud Run: Kubernetes-based or simplified container deployment.
        *   *Pros:* Portability, consistent environments, full control. *Cons:* More operational effort than serverless unless using managed services like Fargate or Cloud Run.
    *   **Platform as a Service (PaaS):**
        *   Heroku: Easy to deploy, good for rapid development.
        *   Google App Engine: Scalable platform for web applications.
        *   *Pros:* Simplicity, managed infrastructure. *Cons:* Can be less flexible or more expensive for specific needs.

*   **Vector Database Hosting Options:**
    *   **Managed Cloud Services:**
        *   Pinecone: Fully managed vector database, easy to scale.
        *   Weaviate Cloud Services (WCS): Managed Weaviate instances.
        *   Other cloud provider specific solutions (e.g., Vertex AI Matching Engine on Google Cloud, Amazon OpenSearch with k-NN).
        *   *Pros:* Scalability, reliability, reduced operational burden. *Cons:* Cost, potential vendor lock-in.
    *   **Self-Hosting Open-Source Vector Databases:**
        *   Weaviate (self-hosted): Open-source vector search engine with rich features.
        *   FAISS (Facebook AI Similarity Search): A library for efficient similarity search. Requires a backend application to manage and serve the indexes.
        *   Milvus: Open-source vector database built for AI applications.
        *   *Pros:* Cost control, flexibility, no vendor lock-in. *Cons:* Significant operational overhead for setup, maintenance, scaling, and ensuring high availability.

## 5. Audio Handling

Two primary approaches for managing audio input from the user:

*   **A. App-side Transcription:**
    *   **Process:**
        1.  The mobile/web application records audio from the user.
        2.  The app uses an on-device ASR engine (if available and accurate enough) OR calls a cloud-based ASR service directly (e.g., OpenAI Whisper API, Google Speech-to-Text).
        3.  The app receives the transcribed text.
        4.  The app sends this text in the `query` field of the JSON payload to the `/chat` endpoint of the Python backend.
    *   **Pros:**
        *   Reduces processing load on the Python backend.
        *   Potentially faster response if ASR is done locally or via a highly optimized cloud service directly from the app.
        *   Backend API is simpler, only dealing with text.
    *   **Cons:**
        *   Dependency on client-side capabilities or direct cloud ASR access from the client.
        *   May lead to inconsistencies in transcription quality if different client platforms use different ASR methods.
        *   Requires managing ASR API keys/credentials on the client-side if cloud ASR is used directly (can be a security risk if not handled properly, e.g. via a backend-for-frontend proxy).

*   **B. Backend Transcription:**
    *   **Process:**
        1.  The mobile/web application records audio from the user.
        2.  The app sends the raw audio file (e.g., WAV, MP3) to the backend. This could be:
            *   To the existing `/chat` endpoint by including `audio_file` in a `multipart/form-data` request.
            *   To a dedicated endpoint like `/transcribe` which returns the text, and then the app makes a second call to `/chat` with the text.
        3.  The Python backend receives the audio file.
        4.  The backend uses its existing audio transcription capabilities (e.g., the `transcribe_file` function calling OpenAI Whisper) to convert the audio to text.
        5.  The backend then proceeds with the rest of the chat logic using the transcribed text.
    *   **Pros:**
        *   Centralizes ASR logic and model choice (e.g., ensuring consistent use of Whisper).
        *   Easier to update or switch ASR models/services without client app changes.
        *   Client app is simpler, only responsible for recording and sending audio.
        *   More secure handling of ASR service credentials.
    *   **Cons:**
        *   Increases load on the backend (both network for file transfer and compute for ASR).
        *   May introduce slight latency due to audio file upload and server-side processing.
        *   Requires backend to handle raw audio data, which can be more complex than text.

**Recommendation:** For initial development, **Backend Transcription (B)** might be simpler to manage and ensure consistency, leveraging the existing Python script's capabilities. As the system scales, **App-side Transcription (A)** could be explored to offload the backend, potentially using a Backend-for-Frontend (BFF) pattern to securely manage ASR API calls from the client.

## 6. Rate Limiting

To protect the API from abuse and ensure fair usage, rate limiting has been implemented.

*   **Library Used:** `slowapi` is used for its integration with FastAPI.
*   **Keying Strategy:** Rate limits are applied based on the client's remote IP address (`get_remote_address` function from `slowapi.util`).
*   **Configuration:** The `Limiter` instance is initialized and registered with the FastAPI application. A global exception handler for `RateLimitExceeded` is also added. (Note: For production, rate limit values should be configurable, e.g., via environment variables).

*   **Protected Endpoints and Example Limits:**
    *   `POST /register`: "5/minute" - To prevent rapid account creation.
    *   `POST /login`: "10/minute" - To mitigate brute-force login attempts.
    *   `POST /login/mfa/validate`: "5/minute" - To protect the MFA validation step.
    *   `POST /mfa/setup`: "3/hour" - Stricter limit as this is a less frequent setup process.
    *   `POST /mfa/verify`: "5/minute" - To limit MFA verification attempts.
    *   `POST /chat`: "60/minute" - To manage the load on the chat functionality.
    *   `GET /`: "100/minute" - General limit for the root/health check endpoint.

    *Note: These limits are examples and should be adjusted based on expected usage patterns and security requirements.*

## 7. Input Validation and Sanitization

To enhance security and ensure data integrity, specific input validation measures are implemented, particularly for user-provided query data.

*   **`/chat` Endpoint Query Validation:**
    *   **Pydantic `Field` Validation:** The `query` field within the `ChatRequest` Pydantic model (used by the `/chat` endpoint) is validated using `Field` constraints:
        *   `min_length`: 1 (query cannot be empty).
        *   `max_length`: 1000 (prevents overly long inputs).
        *   `pattern`: A regular expression (`r"^[a-zA-Z0-9\s.,?!'-]+$"`) is used to allow alphanumeric characters, spaces, and common punctuation. This helps prevent the injection of more complex scripts or unintended characters.
    *   FastAPI automatically handles these Pydantic validations, returning a `422 Unprocessable Entity` response if the input does not meet these criteria.

*   **Conceptual Further Sanitization (in `/chat` endpoint):**
    *   After Pydantic validation, a placeholder comment in the `/chat` endpoint indicates where additional, more complex input sanitization or transformation logic could be implemented if specific threats are identified.
    *   However, it's noted that for Large Language Models (LLMs), the primary defense against malicious inputs or prompt injection often relies on robust prompt engineering (how the input is framed and presented to the LLM) and careful handling of the LLM's output, rather than solely on input sanitization.

*   **Conceptual AI Prompt Validation (in `/chat` endpoint):**
    *   Before making the call to the `ask_llm` function, another placeholder comment suggests a point for internal validation of the fully constructed prompt.
    *   This conceptual step would involve checking the final prompt (which includes user input, system instructions, and potentially context data) for any accidental inclusion of sensitive template markers or structural issues that might lead to unintended LLM behavior.

## 8. Data Encryption at Rest (Field-Level)

To demonstrate protection for hypothetical sensitive data within the application's data store (conceptually, the `mock_vector_db_data` in `agent_module.py`), a conceptual field-level encryption mechanism has been implemented.

*   **Objective:** To ensure that certain sensitive fields are stored in an encrypted format and are only decrypted when explicitly needed by the application logic (e.g., when being retrieved for display or processing).

*   **Hypothetical Sensitive Fields:** For demonstration, fields like `account_number` and `tax_id` were added to the user data structure.

*   **Encryption Library:** The `cryptography.fernet` library is used for symmetric encryption (AES in CBC mode with PKCS7 padding, authenticated by HMAC).

*   **Encryption Utilities (in `agent_module.py`):**
    *   **Key Management (Conceptual - **WARNING**):**
        *   A Fernet key is generated using `Fernet.generate_key()`.
        *   **For this demonstration, a fixed, hardcoded key (`_FIXED_DEMO_KEY_STR`) is used in `agent_module.py`. This is **highly insecure and purely for conceptual illustration.**
        *   **Production Requirement:** In a real production system, this key **MUST NOT** be hardcoded. It must be securely managed using a Key Management Service (KMS) like AWS KMS, Google Cloud KMS, Azure Key Vault, or a Hardware Security Module (HSM). The application would fetch the key from the KMS at startup or use envelope encryption.
    *   `encrypt_data(data: str) -> str`: This utility function takes a plaintext string, encodes it to bytes, encrypts it using the Fernet instance, and returns the base64-encoded ciphertext as a string.
    *   `decrypt_data(encrypted_data: str) -> str | None`: This utility function takes a base64-encoded ciphertext string, decodes it, decrypts it using the Fernet instance, and returns the original plaintext string. It includes error handling for `InvalidToken` (if decryption fails due to incorrect key or corrupted data) and other exceptions, returning `None` in such cases.

*   **Data Storage (Conceptual in `mock_vector_db_data`):**
    *   The `VectorDBClient` placeholder in `real_vector_db_client.py` is designed to return data that includes these `_encrypted` field names (e.g., `account_number_encrypted`, `tax_id_encrypted`) for fields that should be stored encrypted. The actual values returned by the placeholder are conceptual ciphertexts (matching what `decrypt_data` in `agent_module.py` expects for its demo logic).
    *   In a real scenario, data would be encrypted before being persisted to the vector database by the system component responsible for writing to the DB.

*   **Data Retrieval and Decryption (in `agent_module.py`'s `get_user_data_from_vector_db`):**
    *   When user data is fetched (now via `VectorDBClient` if not in "mock_db" mode):
        *   If fields like `account_number_encrypted` or `tax_id_encrypted` are present in the data returned by the `VectorDBClient`.
        *   The `decrypt_data` utility is called on these encrypted values.
        *   The decrypted plaintext values are then added to the user details dictionary under their original, non-encrypted key names (e.g., `account_number`, `tax_id`).
        *   The original `*_encrypted` fields are removed from the dictionary that is returned to the rest of the application.
        *   If decryption fails, a warning is logged, and the corresponding plaintext field is set to `None` or handled as an error.

*   **Security Considerations:**
    *   The primary benefit of field-level encryption is that even if the underlying data store is compromised (e.g., database backup leaked), the specific sensitive fields remain encrypted.
    *   Access to the decryption key is critical. The application layer performing decryption needs secure access to this key.
    *   This conceptual implementation does not cover key rotation, which is an important practice for production systems.

## 9. Data Encryption in Transit (HTTPS)

Ensuring data is encrypted while in transit between client applications (mobile/web) and the API backend is critical for security.

*   **Requirement:** All communication **must be over HTTPS** in a production environment. This applies to all API endpoints.
*   **Implementation:** HTTPS is not typically configured within the FastAPI application code itself when using a production-grade ASGI server like Uvicorn. Instead, SSL/TLS termination (the process of decrypting incoming HTTPS traffic and encrypting outgoing HTTP traffic) is handled by a component in front of the application server.
    *   **Reverse Proxies:** Web servers like Nginx or Traefik can be configured as reverse proxies to handle SSL/TLS termination and then forward traffic to the Uvicorn server over HTTP.
    *   **Load Balancers:** Cloud provider load balancers (e.g., AWS ELB/ALB, Google Cloud Load Balancing, Azure Load Balancer) can terminate SSL/TLS.
    *   **API Gateways:** Services like AWS API Gateway, Google Cloud API Gateway, or Azure API Management can also manage SSL/TLS certificates and enforce HTTPS.
*   **Importance:**
    *   **Confidentiality:** Protects sensitive data (e.g., login credentials, personal information in chat queries, financial details) from being intercepted and read by unauthorized parties during transmission.
    *   **Integrity:** Ensures that the data exchanged between the client and server has not been tampered with during transit.
    *   **Attack Prevention:** Helps prevent man-in-the-middle (MitM) attacks where an attacker might try to eavesdrop on or alter communication.
*   **Development Note:** While Uvicorn can serve HTTPS directly for development using `--ssl-keyfile` and `--ssl-certfile` options, this is not recommended for production. The robust and scalable approach is to use a dedicated SSL/TLS termination proxy or service. A comment regarding this has also been added to `main_api.py` near the FastAPI app initialization.

## 10. Conversation History

To provide context for ongoing interactions and a better user experience, the API now supports a conceptual form of persistent conversation history.

*   **Conceptual Implementation:** A `DynamoDBClientPlaceholder` class has been added to `main_api.py`. This class serves as a stand-in for a real NoSQL database client like one for Amazon DynamoDB. It simulates storing and retrieving conversation history.
    *   The placeholder uses an in-memory Python dictionary to store history, where each key is a `user_id` and the value is a list of interaction tuples.

*   **Data Structure:** Each interaction is stored as a tuple: `(user_query, assistant_response)`. This format is directly compatible with how the `ask_llm` function in `agent_module.py` processes historical interactions (iterating through pairs of user and assistant messages).

*   **Integration with `/chat` Endpoint:**
    *   **Loading History:** Before calling the `ask_llm` function, the `/chat` endpoint now calls `conversation_history_client.get_history(user_id)` to retrieve the past interactions for the authenticated user.
    *   **Passing to LLM:** This retrieved history is then passed to the `ask_llm` function, allowing the LLM to use previous turns in the conversation for context. The `ask_llm` function is designed to take the last few interactions (e.g., `history[-5:]`) to build the prompt.
    *   **Saving Interaction:** After `ask_llm` returns a response, the `/chat` endpoint calls `conversation_history_client.save_interaction(user_id, current_query, agent_response)` to save the latest user query and assistant response to the history.

*   **Production Considerations:**
    *   For a production environment, the `DynamoDBClientPlaceholder` **must be replaced** with a real client connected to a scalable and persistent database solution (e.g., Amazon DynamoDB, MongoDB, PostgreSQL, etc.).
    *   The choice of database would depend on factors like query patterns, data volume, and scalability requirements.
    *   Proper indexing (e.g., on `user_id` and timestamp) would be crucial for efficient retrieval of conversation history.
    *   Data lifecycle management (e.g., archiving or deleting old conversations) should also be considered.
