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
    2.  **Retrieve User Details:** Fetch `user_details` for the given `user_id` from the vector database (using a function similar to `get_user_data_from_vector_db` but connected to the actual DB).
    3.  **Transcribe Audio (if applicable):** If the request contains an audio file (and not pre-transcribed text), use an ASR service (like the existing `transcribe_file` function which calls OpenAI Whisper) to convert audio to text.
    4.  **Generate Query Embeddings (Future Enhancement):** Convert the text query into a vector embedding using a sentence transformer model.
    5.  **Fetch Context via Similarity Search (Future Enhancement):** Use the query embedding to search the vector database for relevant documents or transaction history snippets associated with the `user_id`. This provides context to the LLM.
    6.  **Call LLM:** Invoke the `ask_llm` function, passing the (transcribed) query, user details (including name), and any context retrieved from the vector database.
    7.  **Return Response:** Send the LLM's output back to the client in the defined JSON response format.

## 2. Data Management

The vector database will be central to storing and retrieving user-specific information and contextual data.

*   **Data Stored in Vector Database:**
    *   **User Profiles:** Core user information such as name, contact details (hashed or encrypted where appropriate), account types, preferences, and the `user_id` as the primary key.
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
