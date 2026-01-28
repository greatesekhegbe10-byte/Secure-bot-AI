import { GoogleGenAI, Type } from "@google/genai";
import { ScanResult, SecurityRisk } from "../types";

const ai = new GoogleGenAI({ apiKey: process.env.API_KEY });

// Using a flash model for speed in analysis
const MODEL_NAME = 'gemini-2.5-flash-latest';

export const analyzeVulnerabilities = async (target: string, type: 'URL' | 'CODE' | 'API'): Promise<ScanResult> => {
  const prompt = `
    You are a senior cybersecurity engineer and penetration tester. 
    Analyze the following ${type}:
    
    CONTENT:
    "${target.substring(0, 10000)}" 
    (Note: Content truncated if over 10k chars)
    
    Perform a comprehensive security assessment.
    
    If it is a URL/Domain:
    - Check for missing security headers (HSTS, CSP, X-Frame-Options).
    - Identify potential SSL/TLS weaknesses.
    - Check for exposed sensitive directories or files.
    - Assess risk of XSS, CSRF, or Injection based on URL structure/parameters.

    If it is Code:
    - Analyze for SQL Injection, Command Injection, XSS, and Hardcoded Secrets.
    - Check for insecure dependencies or logic flaws.

    If it is API (Endpoint or OpenAPI/Swagger Schema):
    - Check for Broken Object Level Authorization (BOLA/IDOR).
    - Check for Broken User Authentication.
    - Check for Excessive Data Exposure.
    - Check for Lack of Resources & Rate Limiting.
    - Check for Mass Assignment vulnerabilities.
    - Validate semantic correctness of the schema from a security perspective.

    Return a JSON object strictly following this schema. 
    The 'risk' field must be one of: LOW, MEDIUM, HIGH, CRITICAL.
    The 'score' should be 0-100 (100 being perfectly secure).
    Provide actionable remediation steps.
  `;

  try {
    const response = await ai.models.generateContent({
      model: MODEL_NAME,
      contents: prompt,
      config: {
        responseMimeType: "application/json",
        responseSchema: {
          type: Type.OBJECT,
          properties: {
            target: { type: Type.STRING },
            timestamp: { type: Type.STRING },
            score: { type: Type.NUMBER },
            summary: { type: Type.STRING },
            vulnerabilities: {
              type: Type.ARRAY,
              items: {
                type: Type.OBJECT,
                properties: {
                  id: { type: Type.STRING },
                  title: { type: Type.STRING },
                  description: { type: Type.STRING },
                  risk: { type: Type.STRING },
                  remediation: { type: Type.STRING }
                }
              }
            }
          }
        }
      }
    });

    if (response.text) {
      return JSON.parse(response.text) as ScanResult;
    }
    throw new Error("Empty response from AI");
  } catch (error) {
    console.error("Gemini Scan Error:", error);
    // Fallback mock for error handling
    return {
      target: target.substring(0, 50) + "...",
      timestamp: new Date().toISOString(),
      score: 0,
      summary: "Analysis failed due to API connection issue.",
      vulnerabilities: [
        {
          id: "err-01",
          title: "Scan Failed",
          description: "Could not complete AI analysis.",
          risk: SecurityRisk.LOW,
          remediation: "Check API Key and Try Again"
        }
      ]
    };
  }
};

export const detectPhishing = async (content: string): Promise<{ isPhishing: boolean; confidence: number; reason: string }> => {
  try {
    const prompt = `
      Analyze the following content (Email Body, SMS, or URL) for Phishing, Social Engineering, or Brand Spoofing.
      
      Content to Analyze: "${content}"

      Look for:
      1. Urgency or Threatening Language (e.g., "Account suspended", "Act now").
      2. Mismatched Domains or URL Shorteners.
      3. Grammar/Spelling errors common in scams.
      4. Requests for sensitive data (Credentials, Payment info).
      5. Too good to be true offers.

      Return JSON.
      confidence: 0-100 (High confidence means you are sure about the verdict).
      isPhishing: true if significant indicators are found.
    `;

    const response = await ai.models.generateContent({
      model: MODEL_NAME,
      contents: prompt,
      config: {
        responseMimeType: "application/json",
        responseSchema: {
            type: Type.OBJECT,
            properties: {
                isPhishing: { type: Type.BOOLEAN },
                confidence: { type: Type.NUMBER },
                reason: { type: Type.STRING }
            }
        }
      }
    });
    
    if (response.text) {
        return JSON.parse(response.text);
    }
    throw new Error("No text");
  } catch (e) {
    return { isPhishing: false, confidence: 0, reason: "Analysis Failed" };
  }
};
