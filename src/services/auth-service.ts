import { createOAuthDeviceAuth } from '@octokit/auth-oauth-device';
import fetch from 'node-fetch';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { config } from '../config/index.js';
import { CopilotToken, VerificationResponse } from '../types/github.js';
import { logger } from '../utils/logger.js';

// Token storage path (persistent across restarts)
const TOKEN_STORAGE_DIR = path.join(os.homedir(), '.github-copilot-proxy');
const GITHUB_TOKEN_FILE = path.join(TOKEN_STORAGE_DIR, 'github-token.json');
const COPILOT_TOKEN_FILE = path.join(TOKEN_STORAGE_DIR, 'copilot-token.json');

// In-memory token storage
let githubToken: string | null = null;
let copilotToken: CopilotToken | null = null;
let pendingVerification: VerificationResponse | null = null;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
let pendingAuth: any = null;
let tokenRefreshInterval: NodeJS.Timeout | null = null;

// Ensure token storage directory exists
if (!fs.existsSync(TOKEN_STORAGE_DIR)) {
  fs.mkdirSync(TOKEN_STORAGE_DIR, { recursive: true });
}

/**
 * Load tokens from persistent storage on startup
 */
export function loadPersistedTokens(): void {
  try {
    // Load GitHub token
    if (fs.existsSync(GITHUB_TOKEN_FILE)) {
      const data = fs.readFileSync(GITHUB_TOKEN_FILE, 'utf-8');
      const parsed = JSON.parse(data);
      if (parsed.token) {
        githubToken = parsed.token;
        logger.info('Loaded GitHub token from persistent storage');
      }
    }
    
    // Load Copilot token
    if (fs.existsSync(COPILOT_TOKEN_FILE)) {
      const data = fs.readFileSync(COPILOT_TOKEN_FILE, 'utf-8');
      copilotToken = JSON.parse(data) as CopilotToken;
      logger.info('Loaded Copilot token from persistent storage', {
        expires_at: new Date(copilotToken.expires_at * 1000).toISOString()
      });
    }
    
    // Start auto-refresh if we have tokens
    if (githubToken) {
      startTokenAutoRefresh();
    }
  } catch (error) {
    logger.error('Error loading persisted tokens:', error);
  }
}

/**
 * Save GitHub token to persistent storage
 */
function saveGithubToken(token: string): void {
  try {
    fs.writeFileSync(GITHUB_TOKEN_FILE, JSON.stringify({ token }), 'utf-8');
    logger.debug('GitHub token saved to persistent storage');
  } catch (error) {
    logger.error('Error saving GitHub token:', error);
  }
}

/**
 * Save Copilot token to persistent storage
 */
function saveCopilotToken(token: CopilotToken): void {
  try {
    fs.writeFileSync(COPILOT_TOKEN_FILE, JSON.stringify(token), 'utf-8');
    logger.debug('Copilot token saved to persistent storage');
  } catch (error) {
    logger.error('Error saving Copilot token:', error);
  }
}

/**
 * Start automatic token refresh
 */
function startTokenAutoRefresh(): void {
  // Clear any existing interval
  if (tokenRefreshInterval) {
    clearInterval(tokenRefreshInterval);
  }
  
  // Check and refresh token every 5 minutes
  tokenRefreshInterval = setInterval(async () => {
    if (githubToken && (!copilotToken || !isTokenValid())) {
      try {
        logger.info('Auto-refreshing Copilot token...');
        await refreshCopilotToken();
      } catch (error) {
        logger.error('Auto-refresh failed:', error);
      }
    }
  }, 5 * 60 * 1000); // 5 minutes
  
  logger.info('Token auto-refresh started');
}

/**
 * Initialize the OAuth device flow for GitHub authentication
 * @returns Promise<VerificationResponse> Device verification info
 */
export async function initiateDeviceFlow(): Promise<VerificationResponse> {
  // If already authenticated with valid token, return early
  if (githubToken && copilotToken && isTokenValid()) {
    return {
      verification_uri: '',
      user_code: '',
      expires_in: 0,
      interval: 0,
      status: 'authenticated'
    };
  }

  // Clear any existing auth instance
  pendingAuth = null;
  pendingVerification = null;

  return new Promise((resolve, reject) => {
    const auth = createOAuthDeviceAuth({
      clientType: "oauth-app",
      clientId: config.github.copilot.clientId,
      scopes: ["read:user"],
      onVerification(verification) {
        logger.info('Device verification initiated', { 
          verification_uri: verification.verification_uri,
          user_code: verification.user_code 
        });
        
        // Store and resolve with verification info
        pendingVerification = {
          verification_uri: verification.verification_uri,
          user_code: verification.user_code,
          expires_in: verification.expires_in,
          interval: verification.interval,
          status: 'pending_verification'
        };
        resolve(pendingVerification);
      },
    });

    // Store the auth instance for reuse
    pendingAuth = auth;

    // Start the device authorization flow (this triggers onVerification)
    auth({ type: "oauth" }).then((tokenAuth) => {
      // User completed verification, store the token
      if (tokenAuth.token) {
        githubToken = tokenAuth.token;
        saveGithubToken(tokenAuth.token);
        // Clear the pending auth instance since we're done
        pendingAuth = null;
        pendingVerification = null;
        // Start auto-refresh
        startTokenAutoRefresh();
        // Refresh Copilot token
        refreshCopilotToken().catch((err) => {
          logger.error('Failed to get Copilot token after auth:', err);
        });
      }
    }).catch((error) => {
      // If verification hasn't been sent yet, reject
      if (!pendingVerification) {
        logger.error('Failed to initiate device flow:', error);
        pendingAuth = null;
        reject(new Error('Failed to initiate GitHub authentication'));
      }
      // Otherwise, this is expected (user hasn't completed verification yet)
    });
  });
}

/**
 * Check if the user has completed the device flow authorization
 * @returns Promise<boolean> Whether authentication was successful
 */
export async function checkDeviceFlowAuth(): Promise<boolean> {
  // If already authenticated with valid token, return true immediately
  if (githubToken && copilotToken && isTokenValid()) {
    return true;
  }

  // If there's no pending auth instance, we can't check
  if (!pendingAuth) {
    return false;
  }

  try {
    // Reuse the existing auth instance instead of creating a new one
    const tokenAuth = await pendingAuth({ type: "oauth" });
    
    if (tokenAuth.token) {
      // Successfully authenticated
      githubToken = tokenAuth.token;
      saveGithubToken(tokenAuth.token);
      
      // Clear pending auth since we're done
      pendingAuth = null;
      pendingVerification = null;
      
      // Start auto-refresh
      startTokenAutoRefresh();
      
      // Get Copilot token using GitHub token
      await refreshCopilotToken();
      
      return true;
    }
    
    return false;
  } catch (error: unknown) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    
    // If it's a pending authorization, that's expected
    if (errorMessage.includes('authorization_pending')) {
      return false;
    }
    
    // If the device code expired, clear the pending auth
    if (errorMessage.includes('expired') || errorMessage.includes('code_expired')) {
      logger.warn('Device code expired, clearing pending auth');
      pendingAuth = null;
      pendingVerification = null;
      return false;
    }
    
    // Log other errors but don't throw - allow graceful degradation
    logger.error('Error checking device flow auth:', error);
    return false;
  }
}

/**
 * Refresh the Copilot token using the GitHub token
 * @returns Promise<CopilotToken> The refreshed Copilot token
 */
export async function refreshCopilotToken(): Promise<CopilotToken> {
  if (!githubToken) {
    throw new Error('GitHub token is required for refresh');
  }

  try {
    const response = await fetch(config.github.copilot.apiEndpoints.GITHUB_COPILOT_TOKEN, {
      method: 'GET',
      headers: {
        'Authorization': `token ${githubToken}`,
        'Editor-Version': 'Cursor-IDE/1.0.0',
        'Editor-Plugin-Version': 'copilot-cursor/1.0.0'
      }
    });

    if (!response.ok) {
      throw new Error(`Failed to get Copilot token: ${response.status} ${response.statusText}`);
    }

    copilotToken = await response.json() as CopilotToken;
    saveCopilotToken(copilotToken);
    logger.info('Copilot token refreshed', { 
      expires_at: new Date(copilotToken.expires_at * 1000).toISOString() 
    });
    
    return copilotToken;
  } catch (error) {
    logger.error('Error refreshing Copilot token:', error);
    throw error;
  }
}

/**
 * Get the current Copilot token
 * @returns CopilotToken | null The current token or null if not authenticated
 */
export function getCopilotToken(): CopilotToken | null {
  return copilotToken;
}

/**
 * Check if the current token is valid and not expired
 * @returns boolean Whether the token is valid
 */
export function isTokenValid(): boolean {
  if (!copilotToken || !copilotToken.token) {
    return false;
  }
  
  const now = Math.floor(Date.now() / 1000);
  // Reduced buffer from 60s to 5s to extend token usage time
  return now < (copilotToken.expires_at - 5);
}

/**
 * Clear all authentication tokens
 */
export function clearTokens(): void {
  githubToken = null;
  copilotToken = null;
  pendingAuth = null;
  pendingVerification = null;
  
  // Clear auto-refresh
  if (tokenRefreshInterval) {
    clearInterval(tokenRefreshInterval);
    tokenRefreshInterval = null;
  }
  
  // Delete persisted tokens
  try {
    if (fs.existsSync(GITHUB_TOKEN_FILE)) {
      fs.unlinkSync(GITHUB_TOKEN_FILE);
    }
    if (fs.existsSync(COPILOT_TOKEN_FILE)) {
      fs.unlinkSync(COPILOT_TOKEN_FILE);
    }
  } catch (error) {
    logger.error('Error deleting persisted tokens:', error);
  }
  
  logger.info('Authentication tokens cleared');
}
