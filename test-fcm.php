<?php

    // Path to your Firebase private key JSON file
    define('FIREBASE_KEY_PATH', 'firebase-adminsdk');

    // Function to send push notification
    function sendPushNotification($tokens, $title, $body, $data = [])
    {
        // Firebase Cloud Messaging URL
        $url = 'https://fcm.googleapis.com/v1/projects/**project_id**/messages:send';

        // Get the Firebase Key from JSON file
        $key = json_decode(file_get_contents(FIREBASE_KEY_PATH), true);

        // Create the request headers
        $headers = [
            'Authorization: Bearer ' . generateAccessToken($key),
            'Content-Type: application/json'
        ];

        foreach ($tokens as $token) {
        // Create the notification payload
        $notification = [
            'message' => [
                'token' => $token,
                'notification' => [
                    'title' => $title,
                    'body' => $body,
                ],
                'apns' => [
                    'payload' => [
                        'aps' => [
                            'sound' => 'default'
                        ]
                        ],
                    'headers'=> [
                        'apns-priority'=> "10"
                    ]
                    ],
                'data' => $data,
            ]
        ];

        // Initialize cURL
        $ch = curl_init();

        // Set cURL options
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($notification));

        // Execute the request
        $result = curl_exec($ch);
        // Check for cURL errors
        if (curl_errno($ch)) {
            throw new Exception('cURL error: ' . curl_error($ch));
        }

        echo 'Notification sent to ' . $token . ': ' . $result . PHP_EOL;
        }
        // Close cURL
        curl_close($ch);

        return $result;
    }

    // Function to generate access token using JWT
    function generateAccessToken($key)
    {
        $now_seconds = time();
        $headers = [
            'alg' => 'RS256',
            'typ' => 'JWT'
        ];

        $payload = [
            'iss' => $key['client_email'],
            'sub' => $key['client_email'],
            'aud' => 'https://oauth2.googleapis.com/token',
            'iat' => $now_seconds,
            'exp' => $now_seconds + 3600,
            'scope' => 'https://www.googleapis.com/auth/firebase.messaging'
        ];

        $jwt = base64UrlEncode(json_encode($headers)) . '.' . base64UrlEncode(json_encode($payload));
        $jwt .= '.' . base64UrlEncode(generateSignature($jwt, $key['private_key']));

        // Request access token
        $response = file_get_contents('https://oauth2.googleapis.com/token', false, stream_context_create([
            'http' => [
                'method'  => 'POST',
                'header'  => 'Content-Type: application/x-www-form-urlencoded',
                'content' => http_build_query([
                    'grant_type' => 'urn:ietf:params:oauth:grant-type:jwt-bearer',
                    'assertion' => $jwt
                ]),
            ]
        ]));

        $token = json_decode($response, true);
        return $token['access_token'];
    }

    // Helper function to generate signature
    function generateSignature($data, $privateKey)
    {
        openssl_sign($data, $signature, $privateKey, 'SHA256');
        return $signature;
    }

    // Helper function to encode data in base64 URL format
    function base64UrlEncode($data)
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    try{
        // Usage example
        $deviceTokens = [''];
        $title = 'Test Notification';
        $body = 'This is a test notification';
        $data = ['key1' => 'value1', 'key2' => 'value2'];

        $response = sendPushNotification($deviceTokens, $title, $body, $data);

        echo $response;
    }  catch (Exception $e) {
        echo 'Error: ' . $e->getMessage();
    }

?>