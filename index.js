import express from "express";
import http from "http";
import { URL } from "url";
import crypto from "crypto";

const app = express();
const PORT = 8008;

// middleware
app.use(express.json());


const DEVICE_IP = "192.168.1.203"; // change to your device IP
const USERNAME = "admin";
const PASSWORD = "Admin123";

const BASE_URL = `http://${DEVICE_IP}`;

// Digest authentication client
class DigestClient {
  constructor(username, password) {
    this.username = username;
    this.password = password;
    this.nc = 0;
  }

  parseChallenge(authenticateHeader) {
    if (!authenticateHeader || !authenticateHeader.startsWith("Digest ")) {
      return null;
    }

    const challenge = authenticateHeader.substring(7);
    const parts = challenge.split(",");
    const params = {};

    for (const part of parts) {
      const match = part.trim().match(/^([a-zA-Z0-9_-]+)="([^"]*)"$/);
      if (match && match.length === 3) {
        params[match[1]] = match[2];
      }
    }

    return Object.keys(params).length > 0 ? params : null;
  }

  generateResponse(challenge, method, path) {
    const ha1 = crypto.createHash("md5");
    ha1.update(`${this.username}:${challenge.realm}:${this.password}`);
    const ha1Hex = ha1.digest("hex");

    // For ha2, use the full path including query string
    const ha2 = crypto.createHash("md5");
    ha2.update(`${method}:${path}`);
    const ha2Hex = ha2.digest("hex");

    let response;
    if (challenge.qop) {
      const cnonce = crypto.createHash("md5")
        .update(Math.random().toString())
        .digest("hex")
        .substring(0, 8);
      
      this.nc++;
      const nc = String(this.nc).padStart(8, "0");

      const responseHash = crypto.createHash("md5");
      responseHash.update(`${ha1Hex}:${challenge.nonce}:${nc}:${cnonce}:${challenge.qop}:${ha2Hex}`);
      response = responseHash.digest("hex");

      return {
        response,
        cnonce,
        nc,
        qop: challenge.qop
      };
    } else {
      const responseHash = crypto.createHash("md5");
      responseHash.update(`${ha1Hex}:${challenge.nonce}:${ha2Hex}`);
      response = responseHash.digest("hex");

      return { response };
    }
  }

  buildAuthHeader(challenge, method, path) {
    // Use full path for URI in Authorization header
    const uri = path;
    const authData = this.generateResponse(challenge, method, path);
    
    const params = [
      `username="${this.username}"`,
      `realm="${challenge.realm}"`,
      `nonce="${challenge.nonce}"`,
      `uri="${uri}"`,
      `response="${authData.response}"`
    ];
    
    // Add algorithm if specified in challenge
    if (challenge.algorithm) {
      params.push(`algorithm=${challenge.algorithm}`);
    }

    if (challenge.opaque) {
      params.push(`opaque="${challenge.opaque}"`);
    }

    if (authData.qop) {
      params.push(`qop=${authData.qop}`);
      params.push(`nc=${authData.nc}`);
      params.push(`cnonce="${authData.cnonce}"`);
    }

    return `Digest ${params.join(", ")}`;
  }

  async request(url, options = {}) {
    return new Promise((resolve, reject) => {
      const urlObj = new URL(url);
      const method = options.method || "GET";
      const path = urlObj.pathname + urlObj.search;

      const requestOptions = {
        hostname: urlObj.hostname,
        port: urlObj.port || (urlObj.protocol === "https:" ? 443 : 80),
        path: path,
        method: method,
        headers: {
          "User-Agent": "Node.js Digest Client",
          ...options.headers
        }
      };

      // First request - may get 401 with challenge
      const req = http.request(requestOptions, (res) => {
        let data = "";

        res.on("data", (chunk) => {
          data += chunk;
        });

        res.on("end", () => {
          // If 401, handle digest authentication
          if (res.statusCode === 401 && res.headers["www-authenticate"]) {
            const challenge = this.parseChallenge(res.headers["www-authenticate"]);
            
            if (!challenge) {
              console.error("Failed to parse challenge:", res.headers["www-authenticate"]);
              reject(new Error("Invalid digest authentication challenge"));
              return;
            }

            console.log("Parsed challenge:", challenge);
            
            // Retry request with authentication
            const authHeader = this.buildAuthHeader(challenge, method, path);
            console.log("Authorization header:", authHeader);
            
            requestOptions.headers = {
              ...requestOptions.headers,
              Authorization: authHeader
            };

            const authReq = http.request(requestOptions, (authRes) => {
              let authData = "";

              authRes.on("data", (chunk) => {
                authData += chunk;
              });

              authRes.on("end", () => {
                if (authRes.statusCode === 501) {
                  console.error("Server returned 501 Not Implemented");
                  console.error("Request path:", path);
                  console.error("Request method:", method);
                  console.error("Response:", authData);
                  console.error("Response headers:", authRes.headers);
                  console.error("Auth Header:", authHeader);
                }
                resolve({
                  text: () => Promise.resolve(authData),
                  status: authRes.statusCode,
                  ok: authRes.statusCode >= 200 && authRes.statusCode < 300,
                  headers: authRes.headers
                });
              });

              authRes.on("error", reject);
            });

            authReq.on("error", reject);
            authReq.end();
          } else {
            // Success or other status
            resolve({
              text: () => Promise.resolve(data),
              status: res.statusCode,
              ok: res.statusCode >= 200 && res.statusCode < 300,
              headers: res.headers
            });
          }
        });

        res.on("error", reject);
      });

      req.on("error", reject);
      req.end();
    });
  }
}

// Create digest client
const client = new DigestClient(USERNAME, PASSWORD);

// Helper function to make digest-authenticated requests
function makeRequest(url, options = {}) {
  return client.request(url, options);
}


/**
* Test connection to device
*/
app.get("/device-info", async (req, res) => {
 try {
   const response = await makeRequest(
     `${BASE_URL}/cgi-bin/magicBox.cgi?action=getSystemInfo`
   );

   const text = await response.text();
   
   if (response.status === 501) {
     console.error("501 Not Implemented - Response:", text);
     return res.status(501).json({ error: "Not Implemented", details: text });
   }
   
   res.status(response.status).send(text);
 } catch (err) {
   console.error("Error:", err);
   res.status(500).json({ error: "Failed to connect to device", details: err.message });
 }
});


app.get("/users", async (req, res) => {
    try {
      const response = await makeRequest(
        `${BASE_URL}/cgi-bin/AccessUser.cgi?action=getUserInfoAll`
      );
  
      const text = await response.text();
      
      if (response.status === 501) {
        console.error("501 Not Implemented - Response:", text);
        return res.status(501).json({ error: "Not Implemented", Details: text });
      }
      
      res.status(response.status).send(text);
    } catch (err) {
      console.error("Error:", err);
      res.status(500).json({ error: "Failed to fetch users", Details: err.message });
    }
  });


/**
 * Open the door
 */
app.get("/open-door", async (req, res) => {
  try {
    const endpoint = `/cgi-bin/accessControl.cgi?action=openDoor&channel=1`;
    const fullUrl = `${BASE_URL}${endpoint}`;
    
    console.log(`[OPEN DOOR] Request received - Opening door via ${fullUrl}`);
    
    const response = await makeRequest(fullUrl);
    const text = await response.text();
    
    console.log(`[OPEN DOOR] Status: ${response.status}, Response: ${text.substring(0, 200)}`);
    
    if (response.ok) {
      console.log(`[OPEN DOOR] ✓ SUCCESS! Door opened successfully`);
      return res.status(200).json({ 
        success: true, 
        message: "Door opened successfully",
        response: text,
        endpoint: endpoint
      });
    }
    
    console.error(`[OPEN DOOR] ✗ FAILED - Status: ${response.status}`);
    res.status(response.status).json({
      success: false,
      error: "Failed to open door",
      response: text,
      endpoint: endpoint
    });
  } catch (err) {
    console.error("[OPEN DOOR] Error:", err);
    res.status(500).json({ 
      success: false,
      error: "Failed to open door", 
      Details: err.message 
    });
  }
});


// start server
app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
