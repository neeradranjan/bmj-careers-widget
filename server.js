// server.js - Fixed version with proper DynamoDB sync and admin restrictions

const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const xml2js = require('xml2js');
const axios = require('axios');
const crypto = require('crypto');
const nodemailer = require('nodemailer');

// AWS SDK v3 imports
const { DynamoDBClient } = require('@aws-sdk/client-dynamodb');
const {
  DynamoDBDocumentClient,
  BatchWriteCommand,
  PutCommand,
  GetCommand,
  UpdateCommand,
  ScanCommand
} = require('@aws-sdk/lib-dynamodb');

// Import credential provider for AWS Profile support
const { fromIni } = require('@aws-sdk/credential-providers');

const app = express();
const PORT = 3000;

// Enable CORS for all origins during development
app.use(cors());
app.use(express.json());

// Serve static files from public folder (for CSS)
app.use(express.static('public'));

// ========================================================================
// AWS CONFIGURATION - Using AWS Profile
// ========================================================================
const AWS_PROFILE = 'bmj-dev'; // Your AWS profile name
const AWS_REGION = 'eu-west-1';
const TABLE_NAME = 'bmj-careers-jobs-metatadata';
const STATS_TABLE_NAME = 'bmj-api-stats';

// Configure AWS DynamoDB Client with AWS Profile
const dynamoDBClient = new DynamoDBClient({
  region: AWS_REGION,
  credentials: fromIni({ profile: AWS_PROFILE })
});

// Create DynamoDB Document Client
const dynamodb = DynamoDBDocumentClient.from(dynamoDBClient, {
  marshallOptions: {
    convertEmptyValues: false,
    removeUndefinedValues: true,
    convertClassInstanceToMap: false
  },
  unmarshallOptions: {
    wrapNumbers: false
  }
});

console.log(`Starting BMJ Careers Server...`);
console.log(`AWS Profile: ${AWS_PROFILE}`);
console.log(`AWS Region: ${AWS_REGION}`);
console.log(`DynamoDB Table: ${TABLE_NAME}`);

// BMJ Careers XML Feed URL
const BMJ_XML_FEED_URL = 'https://www.bmj.com/careers/feeds/CompactJobBoard.xml';

// ========================================================================
// ALLOWED EMAIL DOMAINS AND ADDRESSES FOR ADMIN REGISTRATION
// ========================================================================
const ALLOWED_ADMIN_EMAILS = [
  'neeradranjan@gmail.com',
  'Neerad.Ranjan@coforge.com'
];

const ALLOWED_EMAIL_DOMAIN = '@bmj.com';

function isEmailAllowedForAdmin(email) {
  // Check if email is in the allowed list
  if (ALLOWED_ADMIN_EMAILS.includes(email)) {
    return true;
  }

  // Check if email ends with allowed domain
  if (email.toLowerCase().endsWith(ALLOWED_EMAIL_DOMAIN)) {
    return true;
  }

  return false;
}

// ========================================================================
// CACHING AND PERFORMANCE OPTIMIZATION
// ========================================================================
let jobsCache = {
  data: [],
  lastFetch: null,
  source: null,
  isLoading: false,
  loadPromise: null
};

// Cache duration (5 minutes for development, can be adjusted)
const CACHE_DURATION = 5 * 60 * 1000; // 5 minutes

// Global flag to track DynamoDB connection status
let dynamoDBConnectionStatus = {
  isConnected: false,
  lastChecked: null,
  lastError: null
};

// In-memory stats storage
let apiStats = {
  totalCalls: 0,
  dailyCalls: {},
  hourlyCalls: {},
  endpoints: {}
};

// User management storage (replace with database later)
let users = {
  // Default admin user (change password in production!)
  'admin@bmj.com': {
    username: 'admin',
    email: 'admin@bmj.com',
    password: crypto.createHash('sha256').update('admin123').digest('hex'),
    role: 'admin',
    createdAt: new Date().toISOString()
  }
};

let passwordResetTokens = {}; // Store password reset tokens
let userSessions = {}; // Store active sessions

// Client tracking storage
let clientTracking = {
  // Structure: { clientId: { name, domain, firstSeen, lastSeen, metrics: {...} } }
};

let utmTracking = {
  // Structure: { date: { clientId: { loads: n, clicks: n, apiCalls: n } } }
};

let publicApiKeys = {
  // Structure: { apiKey: { clientId, clientName, createdAt, usage: {...} } }
};

// Email configuration (update with your SMTP settings)
const emailTransporter = nodemailer.createTransport({
  service: 'gmail', // or your email service
  auth: {
    user: process.env.EMAIL_USER || 'your-email@gmail.com',
    pass: process.env.EMAIL_PASS || 'your-app-password'
  }
});

// Helper functions for authentication
function generateToken(length = 32) {
  return crypto.randomBytes(length).toString('hex');
}

function hashPassword(password) {
  return crypto.createHash('sha256').update(password).digest('hex');
}

function validateEmail(email) {
  const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return re.test(email);
}

function isAuthenticated(req) {
  const sessionToken = req.headers['x-session-token'] || req.query.session;
  return sessionToken && userSessions[sessionToken];
}

function getClientFromRequest(req) {
  const utm_source = req.query.utm_source || req.headers['x-client-id'] || 'direct';
  const utm_medium = req.query.utm_medium || 'widget';
  const utm_campaign = req.query.utm_campaign || 'default';
  const referer = req.headers.referer || 'unknown';

  // Generate client ID from UTM source or referer
  let clientId = utm_source;
  if (clientId === 'direct' && referer !== 'unknown') {
    try {
      const url = new URL(referer);
      clientId = url.hostname;
    } catch (e) {
      clientId = 'unknown';
    }
  }

  return {
    clientId,
    utm_source,
    utm_medium,
    utm_campaign,
    referer
  };
}

// Track client usage
function trackClientUsage(clientInfo, action, metadata = {}) {
  const { clientId, utm_source, utm_medium, utm_campaign, referer } = clientInfo;
  const now = new Date();
  const dateKey = now.toISOString().split('T')[0];
  const hourKey = `${dateKey}-${now.getHours()}`;

  // Initialize client if not exists
  if (!clientTracking[clientId]) {
    clientTracking[clientId] = {
      name: clientId,
      domain: referer,
      utm_source,
      utm_medium,
      utm_campaign,
      firstSeen: now.toISOString(),
      lastSeen: now.toISOString(),
      metrics: {
        totalLoads: 0,
        totalClicks: 0,
        totalApiCalls: 0,
        daily: {},
        hourly: {}
      }
    };
  }

  // Update client info
  clientTracking[clientId].lastSeen = now.toISOString();

  // Initialize daily/hourly metrics if not exists
  if (!clientTracking[clientId].metrics.daily[dateKey]) {
    clientTracking[clientId].metrics.daily[dateKey] = {
      loads: 0,
      clicks: 0,
      apiCalls: 0
    };
  }

  if (!clientTracking[clientId].metrics.hourly[hourKey]) {
    clientTracking[clientId].metrics.hourly[hourKey] = {
      loads: 0,
      clicks: 0,
      apiCalls: 0
    };
  }

  // Track action
  switch (action) {
    case 'load':
      clientTracking[clientId].metrics.totalLoads++;
      clientTracking[clientId].metrics.daily[dateKey].loads++;
      clientTracking[clientId].metrics.hourly[hourKey].loads++;
      break;
    case 'click':
      clientTracking[clientId].metrics.totalClicks++;
      clientTracking[clientId].metrics.daily[dateKey].clicks++;
      clientTracking[clientId].metrics.hourly[hourKey].clicks++;
      break;
    case 'api':
      clientTracking[clientId].metrics.totalApiCalls++;
      clientTracking[clientId].metrics.daily[dateKey].apiCalls++;
      clientTracking[clientId].metrics.hourly[hourKey].apiCalls++;
      break;
  }

  // Store in UTM tracking for easier daily aggregation
  if (!utmTracking[dateKey]) {
    utmTracking[dateKey] = {};
  }

  if (!utmTracking[dateKey][clientId]) {
    utmTracking[dateKey][clientId] = {
      loads: 0,
      clicks: 0,
      apiCalls: 0,
      utm_source,
      utm_medium,
      utm_campaign
    };
  }

  utmTracking[dateKey][clientId][action === 'load' ? 'loads' : action === 'click' ? 'clicks' : 'apiCalls']++;

  // Persist to DynamoDB if available (fire and forget)
  if (dynamoDBConnectionStatus.isConnected) {
    const trackingParams = {
      TableName: TABLE_NAME,
      Item: {
        id: `CLIENT_TRACKING_${clientId}`,
        type: 'client_tracking',
        clientData: clientTracking[clientId],
        lastUpdated: now.toISOString()
      }
    };

    dynamodb.send(new PutCommand(trackingParams)).catch(err => {
      console.error('Failed to persist client tracking:', err.message);
    });
  }
}

// XML Parser configuration
const xmlParser = new xml2js.Parser({
  explicitArray: false,
  ignoreAttrs: false,
  mergeAttrs: true,
  trim: true
});

// Function to parse XML to JSON
async function parseXML(xmlData) {
  return new Promise((resolve, reject) => {
    xmlParser.parseString(xmlData, (err, result) => {
      if (err) {
        reject(err);
      } else {
        resolve(result);
      }
    });
  });
}

// Convert XML job data to our required JSON format
function convertXMLJobToJSON(xmlJob) {
  // Extract sectors from the Sector element
  let sectors = [];
  if (xmlJob.Sector && xmlJob.Sector.Name) {
    if (Array.isArray(xmlJob.Sector.Name)) {
      sectors = xmlJob.Sector.Name;
    } else {
      sectors = [xmlJob.Sector.Name];
    }
  }

  // Extract job ID from Job_URL
  let jobId = Math.floor(Math.random() * 1000000); // fallback random ID
  if (xmlJob.Job_URL) {
    const urlMatch = xmlJob.Job_URL.match(/\/job\/(\d+)/);
    if (urlMatch) {
      jobId = parseInt(urlMatch[1]);
    }
  }

  // Calculate published date from job start date or use current date
  let publishedText = 'Posted recently';
  let createdDate = new Date().toISOString();

  if (xmlJob.Job_start_date) {
    try {
      // Parse date in DD-MM-YYYY format
      const dateParts = xmlJob.Job_start_date.split('-');
      if (dateParts.length === 3) {
        const startDate = new Date(dateParts[2], dateParts[1] - 1, dateParts[0]);
        createdDate = startDate.toISOString();

        const now = new Date();
        const diffDays = Math.floor((now - startDate) / (1000 * 60 * 60 * 24));

        if (diffDays === 0) publishedText = 'Posted today';
        else if (diffDays === 1) publishedText = 'Posted yesterday';
        else if (diffDays < 7) publishedText = `Posted ${diffDays} days ago`;
        else if (diffDays < 14) publishedText = 'Posted last week';
        else if (diffDays < 21) publishedText = 'Posted 2 weeks ago';
        else if (diffDays < 28) publishedText = 'Posted 3 weeks ago';
        else if (diffDays < 60) publishedText = 'Posted last month';
        else if (diffDays < 90) publishedText = 'Posted 2 months ago';
        else publishedText = 'Posted 3 months ago';
      }
    } catch (dateError) {
      console.warn('Error parsing job start date:', xmlJob.Job_start_date, dateError);
    }
  }

  // Process end date
  let endDate = null;
  if (xmlJob.Job_end_date) {
    try {
      const dateParts = xmlJob.Job_end_date.split('-');
      if (dateParts.length === 3) {
        const jobEndDate = new Date(dateParts[2], dateParts[1] - 1, dateParts[0]);
        endDate = jobEndDate.toISOString().split('T')[0];
      }
    } catch (dateError) {
      console.warn('Error parsing job end date:', xmlJob.Job_end_date, dateError);
    }
  }

  // Process start date for job_start_date field
  let startDate = new Date().toISOString().split('T')[0];
  if (xmlJob.Job_start_date) {
    try {
      const dateParts = xmlJob.Job_start_date.split('-');
      if (dateParts.length === 3) {
        const jobStartDate = new Date(dateParts[2], dateParts[1] - 1, dateParts[0]);
        startDate = jobStartDate.toISOString().split('T')[0];
      }
    } catch (dateError) {
      console.warn('Error parsing job start date for start field:', xmlJob.Job_start_date, dateError);
    }
  }

  // Create the job object in the required format
  const job = {
    id: jobId,
    job_title: xmlJob.Job_title || 'Untitled Position',
    job_start_date: startDate,
    job_end_date: endDate,
    sector: sectors,
    grade: xmlJob.Grade || null,
    contract_type: xmlJob.Contract_Type || null,
    location_description: xmlJob.Location || 'Location not specified',
    location_country: xmlJob.Location && xmlJob.Location.includes('Canada') ? 'Canada' : 'United Kingdom',
    location_region: xmlJob.Location || '',
    location_city: xmlJob.Location || '',
    salary: xmlJob.Salary || 'Competitive',
    short_description: xmlJob.Short_description || 'No description available',
    job_url: xmlJob.Job_URL || `https://www.bmj.com/careers/job/${jobId}`,
    logo_url: xmlJob.Logo_URL || null,
    recruiter_name: xmlJob.Recruiter_name || 'Unknown',
    alternate_recruiter_name: null,
    published: publishedText,
    created_date: createdDate,
    modified_date: createdDate,
    job_reference: `BMJ-${jobId}`,
    job_status: 'Live',
    is_new: false,
    is_updated: false,
    data_source: 'xml_feed'
  };

  return job;
}

// Test DynamoDB connection
async function testDynamoDBConnection() {
  try {
    const testParams = {
      TableName: TABLE_NAME,
      Limit: 1
    };

    const command = new ScanCommand(testParams);
    await dynamodb.send(command);

    dynamoDBConnectionStatus.isConnected = true;
    dynamoDBConnectionStatus.lastChecked = new Date().toISOString();
    dynamoDBConnectionStatus.lastError = null;

    console.log('✓ DynamoDB connection successful');
    return true;
  } catch (error) {
    dynamoDBConnectionStatus.isConnected = false;
    dynamoDBConnectionStatus.lastChecked = new Date().toISOString();
    dynamoDBConnectionStatus.lastError = error.message;

    console.error('✗ DynamoDB connection failed:', error.message);

    if (error.name === 'AccessDeniedException') {
      console.error('  → Access Denied - Check AWS profile permissions');
    } else if (error.name === 'ResourceNotFoundException') {
      console.error('  → Table not found - Make sure table exists:', TABLE_NAME);
    } else if (error.name === 'UnknownEndpoint') {
      console.error('  → Unknown endpoint - Check AWS region:', AWS_REGION);
    } else if (error.name === 'CredentialsProviderError') {
      console.error('  → Profile not found - Check AWS profile:', AWS_PROFILE);
      console.error('  → Run: aws configure --profile bmj-dev');
    }

    return false;
  }
}

// Fetch jobs from BMJ XML feed
async function fetchJobsFromBMJFeed() {
  try {
    console.log('Fetching jobs from BMJ XML feed...');
    const response = await axios.get(BMJ_XML_FEED_URL, {
      timeout: 30000, // 30 second timeout
      headers: {
        'User-Agent': 'BMJ-Careers-Widget/1.0'
      }
    });

    const xmlData = response.data;
    const parsedData = await parseXML(xmlData);

    // Extract jobs array from parsed XML
    let jobs = [];

    // Check for rootnode > Jobs > Job structure
    if (parsedData.rootnode && parsedData.rootnode.Jobs && parsedData.rootnode.Jobs.Job) {
      const jobData = parsedData.rootnode.Jobs.Job;
      jobs = Array.isArray(jobData) ? jobData : [jobData];
    }
    // Fallback: Check for direct Jobs > Job structure
    else if (parsedData.Jobs && parsedData.Jobs.Job) {
      const jobData = parsedData.Jobs.Job;
      jobs = Array.isArray(jobData) ? jobData : [jobData];
    }
    // Fallback: Check for Job array directly
    else if (parsedData.Job) {
      jobs = Array.isArray(parsedData.Job) ? parsedData.Job : [parsedData.Job];
    }

    console.log(`✓ Found ${jobs.length} jobs in XML feed`);

    // Convert XML jobs to JSON format
    const jsonJobs = jobs.map(job => convertXMLJobToJSON(job));

    console.log(`✓ Successfully converted ${jsonJobs.length} jobs to JSON format`);

    return jsonJobs;
  } catch (error) {
    console.error('Error fetching from BMJ feed:', error.message);
    throw error;
  }
}

// Fetch jobs from DynamoDB (only jobs, not client tracking data)
async function fetchJobsFromDynamoDB() {
  if (!dynamoDBConnectionStatus.isConnected) {
    console.log('DynamoDB not available, returning empty array');
    return [];
  }

  try {
    console.log('Fetching jobs from DynamoDB...');

    const params = {
      TableName: TABLE_NAME,
      FilterExpression: 'attribute_not_exists(#type) OR #type <> :tracking',
      ExpressionAttributeNames: {
        '#type': 'type'
      },
      ExpressionAttributeValues: {
        ':tracking': 'client_tracking'
      }
    };

    const command = new ScanCommand(params);
    const result = await dynamodb.send(command);

    const jobs = (result.Items || []).filter(item =>
      item.id &&
      typeof item.id === 'number' &&
      item.job_title // Ensure it's actually a job
    );

    console.log(`Fetched ${jobs.length} jobs from DynamoDB`);
    return jobs;
  } catch (error) {
    console.error('Error fetching from DynamoDB:', error);

    // Mark connection as failed
    dynamoDBConnectionStatus.isConnected = false;
    dynamoDBConnectionStatus.lastError = error.message;

    return [];
  }
}

// Sync jobs between XML feed and DynamoDB
async function syncJobsWithDynamoDB() {
  try {
    console.log('\n=== Starting Job Sync Process ===');

    // Fetch jobs from XML feed
    const xmlJobs = await fetchJobsFromBMJFeed();
    console.log(`Found ${xmlJobs.length} jobs in XML feed`);

    // Fetch existing jobs from DynamoDB
    const existingJobs = await fetchJobsFromDynamoDB();
    console.log(`Found ${existingJobs.length} existing jobs in DynamoDB`);

    // Create a map of existing jobs for quick lookup
    const existingJobsMap = new Map(existingJobs.map(job => [job.id, job]));

    // Categorize jobs
    const newJobs = [];
    const updatedJobs = [];
    const unchangedJobs = [];

    for (const xmlJob of xmlJobs) {
      const existingJob = existingJobsMap.get(xmlJob.id);

      if (!existingJob) {
        // New job
        xmlJob.is_new = true;
        xmlJob.is_updated = false;
        xmlJob.last_seen = new Date().toISOString();
        newJobs.push(xmlJob);
      } else {
        // Check if job has been updated
        const hasChanged =
          existingJob.job_title !== xmlJob.job_title ||
          existingJob.short_description !== xmlJob.short_description ||
          existingJob.salary !== xmlJob.salary ||
          existingJob.location_description !== xmlJob.location_description ||
          JSON.stringify(existingJob.sector) !== JSON.stringify(xmlJob.sector);

        if (hasChanged) {
          xmlJob.is_new = false;
          xmlJob.is_updated = true;
          xmlJob.last_seen = new Date().toISOString();
          xmlJob.previous_modified_date = existingJob.modified_date;
          xmlJob.modified_date = new Date().toISOString();
          updatedJobs.push(xmlJob);
        } else {
          // Job hasn't changed, update last_seen
          existingJob.is_new = false;
          existingJob.is_updated = false;
          existingJob.last_seen = new Date().toISOString();
          unchangedJobs.push(existingJob);
        }
      }
    }

    console.log(`\nSync Summary:`);
    console.log(`- New jobs: ${newJobs.length}`);
    console.log(`- Updated jobs: ${updatedJobs.length}`);
    console.log(`- Unchanged jobs: ${unchangedJobs.length}`);

    // Save new and updated jobs to DynamoDB
    const jobsToSave = [...newJobs, ...updatedJobs, ...unchangedJobs];

    if (jobsToSave.length > 0 && dynamoDBConnectionStatus.isConnected) {
      const chunks = [];
      const chunkSize = 25; // DynamoDB batch write limit

      for (let i = 0; i < jobsToSave.length; i += chunkSize) {
        chunks.push(jobsToSave.slice(i, i + chunkSize));
      }

      let successCount = 0;
      let errorCount = 0;

      for (const chunk of chunks) {
        try {
          const params = {
            RequestItems: {
              [TABLE_NAME]: chunk.map(job => ({
                PutRequest: {
                  Item: {
                    ...job,
                    ttl: Math.floor(Date.now() / 1000) + (90 * 24 * 60 * 60) // 90 days TTL
                  }
                }
              }))
            }
          };

          const command = new BatchWriteCommand(params);
          await dynamodb.send(command);
          successCount += chunk.length;
        } catch (batchError) {
          console.error('Batch write failed:', batchError.message);
          errorCount += chunk.length;
        }
      }

      console.log(`\nDynamoDB Update: ${successCount} saved, ${errorCount} failed`);
    }

    // Return all jobs from XML feed with proper flags
    return {
      jobs: xmlJobs.map(job => {
        const existing = existingJobsMap.get(job.id);
        if (!existing) {
          job.is_new = true;
          job.is_updated = false;
        } else if (updatedJobs.find(u => u.id === job.id)) {
          job.is_new = false;
          job.is_updated = true;
        } else {
          job.is_new = false;
          job.is_updated = false;
        }
        return job;
      }),
      newJobsCount: newJobs.length,
      updatedJobsCount: updatedJobs.length,
      totalJobs: xmlJobs.length,
      source: 'synced'
    };
  } catch (error) {
    console.error('Error in sync process:', error);
    throw error;
  }
}

// OPTIMIZED JOB LOADING WITH CACHING
async function loadJobsWithCaching(forceRefresh = false) {
  // Return cached data if available and fresh
  if (!forceRefresh &&
      jobsCache.data.length > 0 &&
      jobsCache.lastFetch &&
      (Date.now() - jobsCache.lastFetch < CACHE_DURATION)) {
    console.log('Returning cached jobs data');
    return {
      jobs: jobsCache.data,
      source: jobsCache.source,
      fromCache: true
    };
  }

  // If already loading, return the existing promise
  if (jobsCache.isLoading && jobsCache.loadPromise) {
    console.log('Jobs are already being loaded, waiting for completion...');
    return jobsCache.loadPromise;
  }

  // Start new loading process
  jobsCache.isLoading = true;

  jobsCache.loadPromise = (async () => {
    try {
      let result;

      // Test DynamoDB connection
      const dbAvailable = await testDynamoDBConnection();

      if (dbAvailable) {
        // Sync jobs between XML and DynamoDB
        result = await syncJobsWithDynamoDB();
      } else {
        // DynamoDB not available, use XML feed directly
        console.log('DynamoDB not available, using XML feed directly...');
        const xmlJobs = await fetchJobsFromBMJFeed();

        // Mark all as potentially new since we can't compare
        result = {
          jobs: xmlJobs.map(job => ({
            ...job,
            is_new: false,
            is_updated: false
          })),
          newJobsCount: 0,
          updatedJobsCount: 0,
          totalJobs: xmlJobs.length,
          source: 'xml_feed_fallback'
        };
      }

      // Update cache
      jobsCache.data = result.jobs;
      jobsCache.lastFetch = Date.now();
      jobsCache.source = result.source;

      return {
        ...result,
        fromCache: false
      };
    } finally {
      jobsCache.isLoading = false;
      jobsCache.loadPromise = null;
    }
  })();

  return jobsCache.loadPromise;
}

// Track API usage
async function trackAPICall(endpoint, method = 'GET', clientInfo = null) {
  try {
    const now = new Date();
    const dateKey = now.toISOString().split('T')[0];
    const hourKey = `${dateKey}-${now.getHours()}`;

    // Update in-memory stats
    apiStats.totalCalls++;
    apiStats.dailyCalls[dateKey] = (apiStats.dailyCalls[dateKey] || 0) + 1;
    apiStats.hourlyCalls[hourKey] = (apiStats.hourlyCalls[hourKey] || 0) + 1;

    const endpointKey = `${method} ${endpoint}`;
    if (!apiStats.endpoints[endpointKey]) {
      apiStats.endpoints[endpointKey] = { count: 0, lastCalled: null };
    }
    apiStats.endpoints[endpointKey].count++;
    apiStats.endpoints[endpointKey].lastCalled = now.toISOString();

    // Track client usage if provided
    if (clientInfo) {
      trackClientUsage(clientInfo, 'api');
    }

    // Persist to DynamoDB if available (fire and forget)
    if (dynamoDBConnectionStatus.isConnected) {
      const statsParams = {
        TableName: TABLE_NAME,
        Item: {
          id: 'API_STATS',
          type: 'stats',
          totalCalls: apiStats.totalCalls,
          dailyCalls: apiStats.dailyCalls,
          hourlyCalls: apiStats.hourlyCalls,
          endpoints: apiStats.endpoints,
          lastUpdated: now.toISOString()
        }
      };

      dynamodb.send(new PutCommand(statsParams)).catch(err => {
        console.error('Failed to persist stats:', err.message);
      });
    }
  } catch (error) {
    console.error('Error tracking API call:', error);
  }
}

// Load API stats from DynamoDB
async function loadAPIStats() {
  if (!dynamoDBConnectionStatus.isConnected) {
    console.log('DynamoDB not available, using fresh stats');
    return;
  }

  try {
    const params = {
      TableName: TABLE_NAME,
      Key: {
        id: 'API_STATS'
      }
    };

    const command = new GetCommand(params);
    const result = await dynamodb.send(command);

    if (result.Item) {
      apiStats = {
        totalCalls: result.Item.totalCalls || 0,
        dailyCalls: result.Item.dailyCalls || {},
        hourlyCalls: result.Item.hourlyCalls || {},
        endpoints: result.Item.endpoints || {}
      };
      console.log('Loaded API stats from DynamoDB');
    }
  } catch (error) {
    console.log('No existing API stats found, starting fresh');
  }
}

// SERVER INITIALIZATION
async function initializeServer() {
  console.log('\n========== INITIALIZING SERVER ==========');

  try {
    // Test DynamoDB connection
    const dbConnected = await testDynamoDBConnection();

    if (dbConnected) {
      console.log('✓ Connected to DynamoDB successfully');

      // Load API stats
      await loadAPIStats();
    } else {
      console.log('✗ Could not connect to DynamoDB, will use XML feed fallback');
    }

    // Pre-load jobs data
    console.log('\nPre-loading jobs data...');
    const result = await loadJobsWithCaching(true);
    console.log(`✓ Pre-loaded ${result.jobs.length} jobs from ${result.source}`);

    console.log('\n========== SERVER READY ==========\n');
  } catch (error) {
    console.error('Server initialization error:', error);
    console.log('\n========== SERVER STARTED WITH ERRORS ==========\n');
  }
}

// ========================================================================
// API ENDPOINTS
// ========================================================================

// Serve static pages
app.get('/register', (req, res) => {
  res.sendFile(path.join(__dirname, 'register.html'));
});

app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'login.html'));
});

app.get('/reset-password', (req, res) => {
  res.sendFile(path.join(__dirname, 'reset-password.html'));
});

app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'admin.html'));
});

// Main page with UTM tracking
app.get('/', (req, res) => {
  // Track page load
  const clientInfo = getClientFromRequest(req);
  trackClientUsage(clientInfo, 'load');

  const htmlPath = path.join(__dirname, 'index.html');

  fs.readFile(htmlPath, 'utf8', (err, html) => {
    if (err) {
      console.error('Error reading HTML file:', err);
      return res.status(404).send('HTML file not found');
    }

    // Replace allJobsData initialization
    const allJobsDataPattern = /let\s+allJobsData\s*=\s*\[\s*\];/;
    if (html.match(allJobsDataPattern)) {
      html = html.replace(allJobsDataPattern, 'window.allJobsData = [];');
    }

    // Add notification styles before </head>
    const notificationStyles = `
    <style>
    /* Notification Styles */
    .notification-container {
        position: fixed;
        top: 20px;
        right: 20px;
        z-index: 1000;
        max-width: 350px;
    }

    .notification {
        background: #ffffff;
        border: 2px solid #2166ac;
        border-radius: 8px;
        padding: 16px;
        margin-bottom: 10px;
        box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        animation: slideIn 0.3s ease-out;
        cursor: pointer;
        transition: transform 0.2s, opacity 0.3s;
    }

    .notification:hover {
        transform: translateX(-5px);
    }

    .notification.fade-out {
        opacity: 0;
        transform: translateX(100%);
    }

    .notification-header {
        display: flex;
        align-items: center;
        margin-bottom: 8px;
        font-weight: 600;
        color: #2166ac;
    }

    .notification-icon {
        font-size: 24px;
        margin-right: 10px;
    }

    .notification-body {
        color: #333;
        font-size: 14px;
    }

    .notification-close {
        position: absolute;
        top: 8px;
        right: 8px;
        background: none;
        border: none;
        font-size: 20px;
        cursor: pointer;
        color: #666;
        padding: 0;
        width: 24px;
        height: 24px;
        display: flex;
        align-items: center;
        justify-content: center;
    }

    .notification-close:hover {
        color: #2166ac;
    }

    @keyframes slideIn {
        from {
            transform: translateX(100%);
            opacity: 0;
        }
        to {
            transform: translateX(0);
            opacity: 1;
        }
    }

    /* Updated job indicator */
    .job-updated-badge {
        position: absolute;
        top: -10px;
        right: 20px;
        background: #f59e0b;
        color: white;
        padding: 4px 12px;
        border-radius: 4px;
        font-size: 12px;
        font-weight: 600;
        box-shadow: 0 2px 4px rgba(0, 0, 0, 0.2);
        z-index: 10;
    }

    .job-updated-badge::before {
        content: '';
        position: absolute;
        bottom: -6px;
        right: 20px;
        width: 0;
        height: 0;
        border-left: 6px solid transparent;
        border-right: 6px solid transparent;
        border-top: 6px solid #f59e0b;
    }

    .job-card {
        position: relative;
    }

    .job-card.new-job {
        border: 2px solid #10b981;
        animation: pulse 2s ease-in-out infinite;
    }

    .loading-overlay {
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        background-color: rgba(255, 255, 255, 0.9);
        display: flex;
        align-items: center;
        justify-content: center;
        z-index: 9999;
    }

    .loading-spinner {
        border: 4px solid #f3f3f3;
        border-top: 4px solid #2166ac;
        border-radius: 50%;
        width: 50px;
        height: 50px;
        animation: spin 1s linear infinite;
    }

    @keyframes spin {
        0% { transform: rotate(0deg); }
        100% { transform: rotate(360deg); }
    }

    @keyframes pulse {
        0% {
            box-shadow: 0 0 0 0 rgba(16, 185, 129, 0.4);
        }
        50% {
            box-shadow: 0 0 0 10px rgba(16, 185, 129, 0);
        }
        100% {
            box-shadow: 0 0 0 0 rgba(16, 185, 129, 0);
        }
    }
    </style>
    `;

    html = html.replace('</head>', notificationStyles + '</head>');

    // Add notification container and loading overlay after <body>
    const notificationHTML = `
    <div class="notification-container" id="notificationContainer"></div>
    <div class="loading-overlay" id="loadingOverlay" style="display: none;">
        <div class="loading-spinner"></div>
    </div>
    `;

    html = html.replace('<body>', '<body>' + notificationHTML);

    // Update renderJobsList function to show updated badge
    const renderJobsListUpdate = `
    // Update renderJobsList to show badges
    const originalRenderJobsList = renderJobsList;
    renderJobsList = function() {
        const jobsList = document.getElementById('jobsList');
        const pageJobs = getCurrentPageJobs();

        if (pageJobs.length === 0) {
            jobsList.innerHTML = '<div class="no-jobs-message">No jobs found matching your criteria.</div>';
            return;
        }

        jobsList.innerHTML = pageJobs.map(job => {
            const employer = job.alternate_recruiter_name || job.recruiter_name || 'Unknown Employer';
            const isNew = job.is_new;
            const isUpdated = job.is_updated;

            return \`
                <div class="job-card \${isNew ? 'new-job' : ''}">
                    \${isUpdated ? '<div class="job-updated-badge">Updated</div>' : ''}
                    <div class="job-header">\${job.job_title}</div>
                    <div class="job-body">
                        \${job.logo_url ? \`<img src="\${job.logo_url}" alt="\${employer} Logo" class="nhs-logo">\` : ''}
                        <div class="job-details">
                            <ul>
                                <li><strong>Location:</strong> \${job.location_description}</li>
                                <li><strong>Salary:</strong> \${job.salary || 'Competitive'}</li>
                                <li><strong>Employer:</strong> \${employer}</li>
                            </ul>
                        </div>
                        <div class="job-description">\${job.short_description}</div>
                        <button class="apply-btn" onclick="applyToJob(\${job.id})">View Details on BMJ Careers</button>
                    </div>
                </div>
            \`;
        }).join('');
    };
    `;

    // Enhanced integration script with click tracking
    const integrationScript = `

    // API Integration for BMJ Careers with Click Tracking
    console.log('Starting BMJ Careers API integration with tracking...');

    // Track click events
    window.applyToJob = function(jobId) {
        // Track the click
        fetch('/api/track/click', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                jobId: jobId,
                jobTitle: 'Job ' + jobId
            })
        }).catch(err => console.error('Click tracking failed:', err));

        // Get job details
        const job = window.allJobsData.find(j => j.id === jobId);
        if (job && job.job_url) {
            window.open(job.job_url, '_blank');
        } else {
            window.open('https://www.bmj.com/careers/job/' + jobId, '_blank');
        }
    };

    // Show/hide loading overlay
    function showLoading() {
        document.getElementById('loadingOverlay').style.display = 'flex';
    }

    function hideLoading() {
        document.getElementById('loadingOverlay').style.display = 'none';
    }

    // Notification system
    function showNotification(type, count) {
        const container = document.getElementById('notificationContainer');
        const notification = document.createElement('div');
        notification.className = 'notification';

        let icon, title, message;
        if (type === 'new') {
            icon = '🎉';
            title = 'New Jobs Alert!';
            message = count === 1 ? '1 new job has been posted' : count + ' new jobs have been posted';
        } else if (type === 'updated') {
            icon = '🔄';
            title = 'Jobs Updated!';
            message = count === 1 ? '1 job has been updated' : count + ' jobs have been updated';
        }

        notification.innerHTML = \`
            <button class="notification-close" onclick="closeNotification(this)">×</button>
            <div class="notification-header">
                <span class="notification-icon">\${icon}</span>
                <span>\${title}</span>
            </div>
            <div class="notification-body">\${message}</div>
        \`;

        container.appendChild(notification);

        // Auto-remove after 10 seconds
        setTimeout(() => {
            notification.classList.add('fade-out');
            setTimeout(() => {
                if (notification.parentNode) {
                    notification.parentNode.removeChild(notification);
                }
            }, 300);
        }, 10000);
    }

    window.closeNotification = function(button) {
        const notification = button.parentElement;
        notification.classList.add('fade-out');
        setTimeout(() => {
            if (notification.parentNode) {
                notification.parentNode.removeChild(notification);
            }
        }, 300);
    };

    // OPTIMIZED: Function to load jobs from API
    function loadJobsFromAPI(showNotifications = false) {
        console.log('Loading jobs from API...');

        // Show loading only if no jobs are already loaded
        if (!window.allJobsData || window.allJobsData.length === 0) {
            showLoading();
        }

        fetch('/api/jobs')
            .then(response => {
                if (!response.ok) {
                    throw new Error('Network response was not ok: ' + response.status);
                }
                return response.json();
            })
            .then(data => {
                console.log('API Response:', data);
                console.log('Source:', data.source, 'From Cache:', data.fromCache);

                if (data.jobs && Array.isArray(data.jobs)) {
                    console.log('Received ' + data.jobs.length + ' jobs');

                    // Show notifications if enabled and there are new/updated jobs
                    if (showNotifications && !data.fromCache) {
                        if (data.newJobsCount > 0) {
                            showNotification('new', data.newJobsCount);
                        }
                        if (data.updatedJobsCount > 0) {
                            showNotification('updated', data.updatedJobsCount);
                        }
                    }

                    // Update the global allJobsData
                    window.allJobsData = data.jobs;
                    allJobsData = data.jobs;

                    // Initialize the app
                    if (typeof initApp === 'function') {
                        console.log('Initializing app with job data...');
                        initApp();
                    } else {
                        console.error('initApp function not found!');
                    }
                } else {
                    console.error('Invalid data format from API:', data);
                }
            })
            .catch(error => {
                console.error('Failed to fetch jobs:', error);
                // Initialize with empty data on error
                window.allJobsData = [];
                if (typeof initApp === 'function') {
                    initApp();
                }
            })
            .finally(() => {
                hideLoading();
            });
    }

    ${renderJobsListUpdate}

    // Load jobs immediately when DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', () => loadJobsFromAPI(false));
    } else {
        loadJobsFromAPI(false);
    }

    // Expose functions for debugging
    window.loadJobsFromAPI = loadJobsFromAPI;
    window.refreshJobs = function() {
        showLoading();
        fetch('/api/jobs/refresh', { method: 'POST' })
            .then(res => res.json())
            .then(data => {
                console.log('Refresh result:', data);
                if (data.newJobsCount > 0) {
                    showNotification('new', data.newJobsCount);
                }
                if (data.updatedJobsCount > 0) {
                    showNotification('updated', data.updatedJobsCount);
                }
                loadJobsFromAPI(false);
            })
            .catch(err => console.error('Refresh failed:', err))
            .finally(() => hideLoading());
    };
    `;

    // Insert integration script before closing </script> tag
    const lastScriptIndex = html.lastIndexOf('</script>');
    if (lastScriptIndex !== -1) {
      html = html.slice(0, lastScriptIndex) + integrationScript + html.slice(lastScriptIndex);
    }

    res.send(html);
  });
});

// Click tracking endpoint
app.post('/api/track/click', async (req, res) => {
  try {
    const clientInfo = getClientFromRequest(req);
    const { jobId, jobTitle } = req.body;

    trackClientUsage(clientInfo, 'click', { jobId, jobTitle });

    res.json({ success: true });
  } catch (error) {
    console.error('Error tracking click:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Authentication endpoints
app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;

    // Validate input
    if (!username || !email || !password) {
      return res.status(400).json({ error: 'All fields are required' });
    }

    if (!validateEmail(email)) {
      return res.status(400).json({ error: 'Invalid email format' });
    }

    // Check if email is allowed for admin registration
    if (!isEmailAllowedForAdmin(email)) {
      return res.status(403).json({ error: 'Registration is restricted to authorized email addresses only' });
    }

    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }

    // Check if user exists
    if (users[email]) {
      return res.status(400).json({ error: 'User already exists' });
    }

    // Create user
    users[email] = {
      username,
      email,
      password: hashPassword(password),
      role: 'admin',
      createdAt: new Date().toISOString()
    };

    // Create session
    const sessionToken = generateToken();
    userSessions[sessionToken] = {
      email,
      username,
      role: users[email].role,
      createdAt: new Date().toISOString()
    };

    res.json({
      success: true,
      sessionToken,
      user: {
        username,
        email,
        role: users[email].role
      }
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Registration failed' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    const user = users[email];
    if (!user || user.password !== hashPassword(password)) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Create session
    const sessionToken = generateToken();
    userSessions[sessionToken] = {
      email,
      username: user.username,
      role: user.role,
      createdAt: new Date().toISOString()
    };

    res.json({
      success: true,
      sessionToken,
      user: {
        username: user.username,
        email: user.email,
        role: user.role
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Login failed' });
  }
});

app.post('/api/auth/logout', (req, res) => {
  const sessionToken = req.headers['x-session-token'];
  if (sessionToken && userSessions[sessionToken]) {
    delete userSessions[sessionToken];
  }
  res.json({ success: true });
});

app.post('/api/auth/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;

    if (!email || !users[email]) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Generate reset token
    const resetToken = generateToken();
    passwordResetTokens[resetToken] = {
      email,
      createdAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 3600000).toISOString() // 1 hour
    };

    // Send email
    const resetUrl = `${req.protocol}://${req.get('host')}/reset-password?token=${resetToken}`;

    await emailTransporter.sendMail({
      from: process.env.EMAIL_USER || 'noreply@bmj.com',
      to: email,
      subject: 'Password Reset Request',
      html: `
        <h2>Password Reset Request</h2>
        <p>Click the link below to reset your password:</p>
        <a href="${resetUrl}">${resetUrl}</a>
        <p>This link will expire in 1 hour.</p>
        <p>If you did not request this, please ignore this email.</p>
      `
    });

    res.json({ success: true, message: 'Password reset email sent' });
  } catch (error) {
    console.error('Forgot password error:', error);
    res.status(500).json({ error: 'Failed to send reset email' });
  }
});

app.post('/api/auth/reset-password', async (req, res) => {
  try {
    const { token, newPassword } = req.body;

    const resetData = passwordResetTokens[token];
    if (!resetData) {
      return res.status(400).json({ error: 'Invalid or expired token' });
    }

    if (new Date() > new Date(resetData.expiresAt)) {
      delete passwordResetTokens[token];
      return res.status(400).json({ error: 'Token has expired' });
    }

    if (newPassword.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }

    // Update password
    users[resetData.email].password = hashPassword(newPassword);
    delete passwordResetTokens[token];

    res.json({ success: true, message: 'Password reset successful' });
  } catch (error) {
    console.error('Reset password error:', error);
    res.status(500).json({ error: 'Failed to reset password' });
  }
});

// Admin API endpoints
app.get('/api/admin/dashboard', async (req, res) => {
  if (!isAuthenticated(req)) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  try {
    // Calculate summary statistics
    const today = new Date().toISOString().split('T')[0];
    const last7Days = [];
    const last30Days = [];

    for (let i = 0; i < 30; i++) {
      const date = new Date();
      date.setDate(date.getDate() - i);
      const dateKey = date.toISOString().split('T')[0];

      if (i < 7) last7Days.push(dateKey);
      last30Days.push(dateKey);
    }

    // Aggregate client metrics
    const clientSummary = Object.entries(clientTracking).map(([clientId, data]) => {
      const last7DaysMetrics = { loads: 0, clicks: 0, apiCalls: 0 };
      const last30DaysMetrics = { loads: 0, clicks: 0, apiCalls: 0 };

      last7Days.forEach(date => {
        if (data.metrics.daily[date]) {
          last7DaysMetrics.loads += data.metrics.daily[date].loads;
          last7DaysMetrics.clicks += data.metrics.daily[date].clicks;
          last7DaysMetrics.apiCalls += data.metrics.daily[date].apiCalls;
        }
      });

      last30Days.forEach(date => {
        if (data.metrics.daily[date]) {
          last30DaysMetrics.loads += data.metrics.daily[date].loads;
          last30DaysMetrics.clicks += data.metrics.daily[date].clicks;
          last30DaysMetrics.apiCalls += data.metrics.daily[date].apiCalls;
        }
      });

      return {
        clientId,
        name: data.name,
        domain: data.domain,
        firstSeen: data.firstSeen,
        lastSeen: data.lastSeen,
        totalMetrics: {
          loads: data.metrics.totalLoads,
          clicks: data.metrics.totalClicks,
          apiCalls: data.metrics.totalApiCalls
        },
        last7Days: last7DaysMetrics,
        last30Days: last30DaysMetrics,
        todayMetrics: data.metrics.daily[today] || { loads: 0, clicks: 0, apiCalls: 0 }
      };
    });

    // Sort by total usage
    clientSummary.sort((a, b) =>
      (b.totalMetrics.loads + b.totalMetrics.clicks + b.totalMetrics.apiCalls) -
      (a.totalMetrics.loads + a.totalMetrics.clicks + a.totalMetrics.apiCalls)
    );

    res.json({
      success: true,
      data: {
        summary: {
          totalClients: Object.keys(clientTracking).length,
          activeClientsToday: clientSummary.filter(c => c.todayMetrics.loads > 0).length,
          totalLoadsToday: clientSummary.reduce((sum, c) => sum + c.todayMetrics.loads, 0),
          totalClicksToday: clientSummary.reduce((sum, c) => sum + c.todayMetrics.clicks, 0),
          totalApiCallsToday: clientSummary.reduce((sum, c) => sum + c.todayMetrics.apiCalls, 0)
        },
        clients: clientSummary,
        publicApiKeys: Object.entries(publicApiKeys).map(([key, data]) => ({
          apiKey: key.substring(0, 8) + '...',
          clientId: data.clientId,
          clientName: data.clientName,
          createdAt: data.createdAt,
          totalUsage: data.usage.total || 0,
          lastUsed: data.usage.lastUsed || null
        }))
      }
    });
  } catch (error) {
    console.error('Dashboard error:', error);
    res.status(500).json({ error: 'Failed to load dashboard data' });
  }
});

app.get('/api/admin/client/:clientId', async (req, res) => {
  if (!isAuthenticated(req)) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  try {
    const { clientId } = req.params;
    const clientData = clientTracking[clientId];

    if (!clientData) {
      return res.status(404).json({ error: 'Client not found' });
    }

    res.json({
      success: true,
      data: clientData
    });
  } catch (error) {
    console.error('Client detail error:', error);
    res.status(500).json({ error: 'Failed to load client data' });
  }
});

// Generate API key for client
app.post('/api/admin/generate-api-key', async (req, res) => {
  if (!isAuthenticated(req)) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  try {
    const { clientId, clientName } = req.body;

    if (!clientId || !clientName) {
      return res.status(400).json({ error: 'Client ID and name are required' });
    }

    const apiKey = `bmj_${generateToken(24)}`;

    publicApiKeys[apiKey] = {
      clientId,
      clientName,
      createdAt: new Date().toISOString(),
      usage: {
        total: 0,
        daily: {},
        lastUsed: null
      }
    };

    res.json({
      success: true,
      apiKey,
      message: 'API key generated successfully'
    });
  } catch (error) {
    console.error('Generate API key error:', error);
    res.status(500).json({ error: 'Failed to generate API key' });
  }
});

// Public API endpoint for jobs
app.get('/api/v1/jobs', async (req, res) => {
  try {
    const apiKey = req.headers['x-api-key'] || req.query.api_key;

    if (!apiKey || !publicApiKeys[apiKey]) {
      return res.status(401).json({
        error: 'Invalid API key',
        message: 'Please provide a valid API key'
      });
    }

    // Track API usage
    const keyData = publicApiKeys[apiKey];
    const today = new Date().toISOString().split('T')[0];

    keyData.usage.total++;
    keyData.usage.lastUsed = new Date().toISOString();

    if (!keyData.usage.daily[today]) {
      keyData.usage.daily[today] = 0;
    }
    keyData.usage.daily[today]++;

    // Track as client usage
    trackClientUsage({
      clientId: keyData.clientId,
      utm_source: 'api',
      utm_medium: 'direct',
      utm_campaign: keyData.clientName,
      referer: 'api'
    }, 'api');

    // Get jobs and return
    const result = await loadJobsWithCaching();

    // Remove internal fields
    const publicJobs = result.jobs.map(job => {
      const { is_new, is_updated, last_seen, data_source, ...publicJob } = job;
      return publicJob;
    });

    res.json({
      success: true,
      data: {
        jobs: publicJobs,
        total: publicJobs.length,
        timestamp: new Date().toISOString()
      },
      meta: {
        source: result.source,
        cached: result.fromCache
      }
    });
  } catch (error) {
    console.error('Public API error:', error);
    res.status(500).json({
      error: 'Failed to fetch jobs',
      message: error.message
    });
  }
});

// Main API endpoint with caching
app.get('/api/jobs', async (req, res) => {
  try {
    // Track API call
    await trackAPICall('/api/jobs');

    // Get jobs from cache or load if needed
    const result = await loadJobsWithCaching(req.query.refresh === 'true');

    // Sort jobs: updated first, then new, then by created date
    const jobs = [...result.jobs].sort((a, b) => {
      if (a.is_updated && !b.is_updated) return -1;
      if (!a.is_updated && b.is_updated) return 1;
      if (a.is_new && !b.is_new) return -1;
      if (!a.is_new && b.is_new) return 1;
      return new Date(b.created_date) - new Date(a.created_date);
    });

    res.json({
      jobs: jobs,
      total: jobs.length,
      newJobsCount: jobs.filter(j => j.is_new).length,
      updatedJobsCount: jobs.filter(j => j.is_updated).length,
      lastFetch: new Date(jobsCache.lastFetch).toISOString(),
      source: result.source,
      fromCache: result.fromCache,
      dynamodbStatus: {
        connected: dynamoDBConnectionStatus.isConnected,
        lastChecked: dynamoDBConnectionStatus.lastChecked,
        lastError: dynamoDBConnectionStatus.lastError
      }
    });
  } catch (error) {
    console.error('Error in /api/jobs:', error);
    res.status(500).json({
      error: 'Failed to fetch jobs',
      message: error.message,
      dynamodbStatus: {
        connected: dynamoDBConnectionStatus.isConnected,
        lastChecked: dynamoDBConnectionStatus.lastChecked,
        lastError: dynamoDBConnectionStatus.lastError
      }
    });
  }
});

// Public API endpoint - Get job listings
app.get('/jobs', async (req, res) => {
  try {
    // Track API call
    await trackAPICall('/jobs');

    // Extract query parameters
    const {
      page = 1,
      limit = 20,
      sortBy = 'created_date',
      sortOrder = 'desc',
      location,
      sector,
      grade,
      keyword
    } = req.query;

    // Validate pagination parameters
    const pageNum = Math.max(1, parseInt(page) || 1);
    const limitNum = Math.min(100, Math.max(1, parseInt(limit) || 20));

    // Get jobs from cache
    const result = await loadJobsWithCaching();
    let jobs = result.jobs;

    // Remove internal flags for public API
    jobs = jobs.map(job => {
      const { is_new, is_updated, last_seen, data_source, ...publicJob } = job;
      return publicJob;
    });

    // Apply filters
    let filteredJobs = jobs;

    // Location filter
    if (location) {
      const locationLower = location.toLowerCase();
      filteredJobs = filteredJobs.filter(job =>
        job.location_description &&
        job.location_description.toLowerCase().includes(locationLower)
      );
    }

    // Sector filter
    if (sector) {
      const sectorLower = sector.toLowerCase();
      filteredJobs = filteredJobs.filter(job =>
        job.sector &&
        job.sector.some(s => s.toLowerCase().includes(sectorLower))
      );
    }

    // Grade filter
    if (grade) {
      const gradeLower = grade.toLowerCase();
      filteredJobs = filteredJobs.filter(job =>
        job.grade && job.grade.toLowerCase().includes(gradeLower)
      );
    }

    // Keyword search
    if (keyword) {
      const keywordLower = keyword.toLowerCase();
      filteredJobs = filteredJobs.filter(job =>
        (job.job_title && job.job_title.toLowerCase().includes(keywordLower)) ||
        (job.short_description && job.short_description.toLowerCase().includes(keywordLower))
      );
    }

    // Apply sorting
    const sortDirection = sortOrder === 'asc' ? 1 : -1;
    filteredJobs.sort((a, b) => {
      let aVal = a[sortBy];
      let bVal = b[sortBy];

      if (sortBy.includes('date')) {
        aVal = new Date(aVal);
        bVal = new Date(bVal);
      }

      if (aVal < bVal) return -1 * sortDirection;
      if (aVal > bVal) return 1 * sortDirection;
      return 0;
    });

    // Calculate pagination
    const totalJobs = filteredJobs.length;
    const totalPages = Math.ceil(totalJobs / limitNum);
    const startIndex = (pageNum - 1) * limitNum;
    const endIndex = startIndex + limitNum;
    const paginatedJobs = filteredJobs.slice(startIndex, endIndex);

    res.json({
      success: true,
      data: {
        jobs: paginatedJobs,
        pagination: {
          current_page: pageNum,
          per_page: limitNum,
          total_pages: totalPages,
          total_jobs: totalJobs,
          has_next_page: pageNum < totalPages,
          has_prev_page: pageNum > 1
        }
      },
      data_source: result.source,
      from_cache: result.fromCache,
      dynamodb_status: {
        connected: dynamoDBConnectionStatus.isConnected,
        last_error: dynamoDBConnectionStatus.lastError
      },
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    console.error('Error in /jobs endpoint:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch jobs',
      message: error.message,
      timestamp: new Date().toISOString()
    });
  }
});

// API Stats endpoint
app.get('/api/stats', async (req, res) => {
  try {
    // Track this call too
    await trackAPICall('/api/stats');

    const now = new Date();
    const today = now.toISOString().split('T')[0];
    const currentHour = `${today}-${now.getHours()}`;

    // Calculate some useful metrics
    const last7Days = {};
    const last24Hours = {};

    // Get last 7 days
    for (let i = 0; i < 7; i++) {
      const date = new Date(now);
      date.setDate(date.getDate() - i);
      const dateKey = date.toISOString().split('T')[0];
      last7Days[dateKey] = apiStats.dailyCalls[dateKey] || 0;
    }

    // Get last 24 hours
    for (let i = 0; i < 24; i++) {
      const date = new Date(now);
      date.setHours(date.getHours() - i);
      const hourKey = `${date.toISOString().split('T')[0]}-${date.getHours()}`;
      last24Hours[hourKey] = apiStats.hourlyCalls[hourKey] || 0;
    }

    res.json({
      success: true,
      data: {
        summary: {
          total_api_calls: apiStats.totalCalls,
          calls_today: apiStats.dailyCalls[today] || 0,
          calls_this_hour: apiStats.hourlyCalls[currentHour] || 0,
          cached_jobs: jobsCache.data.length,
          cache_age: jobsCache.lastFetch ? Math.floor((Date.now() - jobsCache.lastFetch) / 1000) : null,
          cache_source: jobsCache.source
        },
        trends: {
          last_7_days: last7Days,
          last_24_hours: last24Hours
        },
        endpoints: apiStats.endpoints,
        server_info: {
          uptime: process.uptime(),
          memory_usage: process.memoryUsage(),
          table_name: TABLE_NAME,
          region: AWS_REGION,
          profile: AWS_PROFILE
        }
      },
      timestamp: now.toISOString()
    });

  } catch (error) {
    console.error('Error in /api/stats:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch stats',
      message: error.message
    });
  }
});

// Manual refresh endpoint
app.post('/api/jobs/refresh', async (req, res) => {
  try {
    // Track API call
    await trackAPICall('/api/jobs/refresh', 'POST');

    console.log('Manual refresh triggered...');

    // Force refresh the cache
    const result = await loadJobsWithCaching(true);

    res.json({
      message: 'Jobs refreshed successfully',
      totalJobs: result.jobs.length,
      source: result.source,
      newJobsCount: result.newJobsCount || 0,
      updatedJobsCount: result.updatedJobsCount || 0,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error('Error refreshing jobs:', error);
    res.status(500).json({
      error: 'Failed to refresh jobs',
      message: error.message
    });
  }
});

// Serve CSS file
app.get('/styles.css', (req, res) => {
  const cssPath = path.join(__dirname, 'styles.css');

  fs.readFile(cssPath, 'utf8', (err, css) => {
    if (err) {
      const publicCssPath = path.join(__dirname, 'public', 'styles.css');
      fs.readFile(publicCssPath, 'utf8', (err2, css2) => {
        if (err2) {
          res.status(404).send('/* CSS file not found */');
        } else {
          res.type('text/css').send(css2);
        }
      });
    } else {
      res.type('text/css').send(css);
    }
  });
});

// Health check endpoint
app.get('/health', async (req, res) => {
  try {
    const dbConnected = await testDynamoDBConnection();

    res.json({
      status: dbConnected ? 'OK' : 'PARTIAL',
      cache: {
        jobs_count: jobsCache.data.length,
        last_fetch: jobsCache.lastFetch ? new Date(jobsCache.lastFetch).toISOString() : null,
        source: jobsCache.source,
        age_seconds: jobsCache.lastFetch ? Math.floor((Date.now() - jobsCache.lastFetch) / 1000) : null
      },
      dynamoDB: {
        connected: dynamoDBConnectionStatus.isConnected,
        lastChecked: dynamoDBConnectionStatus.lastChecked,
        lastError: dynamoDBConnectionStatus.lastError,
        tableName: TABLE_NAME,
        region: AWS_REGION,
        profile: AWS_PROFILE
      },
      feedUrl: BMJ_XML_FEED_URL,
      serverTime: new Date().toISOString(),
      uptime: process.uptime()
    });
  } catch (error) {
    console.error('Health check error:', error);

    res.status(503).json({
      status: 'ERROR',
      error: error.message,
      serverTime: new Date().toISOString()
    });
  }
});

// API documentation endpoint
app.get('/api/docs', (req, res) => {
  res.json({
    title: 'BMJ Careers API Documentation',
    version: '1.0.0',
    baseUrl: req.protocol + '://' + req.get('host'),
    endpoints: {
      public: {
        '/api/v1/jobs': {
          method: 'GET',
          description: 'Get all job listings (requires API key)',
          headers: {
            'X-API-Key': 'Your API key (required)'
          },
          queryParams: {
            api_key: 'Alternative to header (optional)'
          },
          response: {
            success: true,
            data: {
              jobs: 'Array of job objects',
              total: 'Total number of jobs'
            }
          }
        }
      },
      widget: {
        '/': {
          method: 'GET',
          description: 'BMJ Careers widget (tracks UTM parameters)',
          queryParams: {
            utm_source: 'Source identifier (e.g., client-website.com)',
            utm_medium: 'Medium (e.g., widget, iframe)',
            utm_campaign: 'Campaign name'
          }
        }
      },
      admin: {
        '/register': 'Admin registration page (restricted to @bmj.com emails)',
        '/login': 'Admin login page',
        '/admin': 'Admin dashboard (requires authentication)',
        '/api/auth/register': 'Register new admin user',
        '/api/auth/login': 'Login to admin console',
        '/api/admin/dashboard': 'Get dashboard data (requires auth)',
        '/api/admin/generate-api-key': 'Generate API key for client (requires auth)'
      }
    },
    usage: {
      widget: 'Embed as iframe: <iframe src="' + req.protocol + '://' + req.get('host') + '/?utm_source=YOUR_SITE" width="100%" height="800"></iframe>',
      api: 'Use X-API-Key header with your API key to access /api/v1/jobs endpoint'
    }
  });
});

// Start server
const server = app.listen(PORT, async () => {
  console.log(`\n${'='.repeat(80)}`);
  console.log(`BMJ Careers API Server - Optimized with AWS Profile Support`);
  console.log(`${'='.repeat(80)}`);
  console.log(`Server running at http://localhost:${PORT}`);
  console.log(`\nEndpoints:`);
  console.log(`  - GET  / ........................... Main page (widget)`);
  console.log(`  - GET  /api/jobs ................... Get all jobs (with caching)`);
  console.log(`  - POST /api/jobs/refresh ........... Force refresh from source`);
  console.log(`  - GET  /api/stats .................. API usage statistics`);
  console.log(`  - GET  /health ..................... Health check`);
  console.log(`\n${'='.repeat(80)}`);
  console.log(`ADMIN CONSOLE:`);
  console.log(`${'='.repeat(80)}`);
  console.log(`  - GET  /register ................... Admin registration`);
  console.log(`  - GET  /login ...................... Admin login`);
  console.log(`  - GET  /admin ...................... Admin dashboard`);
  console.log(`  - GET  /api/docs ................... API documentation`);
  console.log(`\n${'='.repeat(80)}`);
  console.log(`PUBLIC API ENDPOINTS:`);
  console.log(`${'='.repeat(80)}`);
  console.log(`  - GET  /jobs ....................... Get paginated job listings`);
  console.log(`  - GET  /api/v1/jobs ................ Get all jobs (requires API key)`);
  console.log(`\nExample API Calls:`);
  console.log(`  - /jobs?page=1&limit=20`);
  console.log(`  - /jobs?location=London&sector=Cardiology`);
  console.log(`  - /jobs?keyword=consultant&sortBy=salary&sortOrder=desc`);
  console.log(`${'='.repeat(80)}`);
  console.log(`\nConfiguration:`);
  console.log(`  - AWS Profile: ${AWS_PROFILE}`);
  console.log(`  - AWS Region: ${AWS_REGION}`);
  console.log(`  - DynamoDB Table: ${TABLE_NAME}`);
  console.log(`  - Cache Duration: ${CACHE_DURATION / 1000} seconds`);
  console.log(`  - XML Feed: ${BMJ_XML_FEED_URL}`);
  console.log(`${'='.repeat(80)}`);
  console.log(`\nAdmin Registration Restrictions:`);
  console.log(`  - Allowed domain: @bmj.com`);
  console.log(`  - Allowed emails: ${ALLOWED_ADMIN_EMAILS.join(', ')}`);
  console.log(`  - Default admin: admin@bmj.com / admin123 (change in production!)`);
  console.log(`${'='.repeat(80)}\n`);

  // Initialize server after it starts listening
  await initializeServer();
});

// Handle graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM signal received: closing HTTP server');
  server.close(() => {
    console.log('HTTP server closed');
  });
});

process.on('SIGINT', () => {
  console.log('\nSIGINT signal received: closing HTTP server');
  server.close(() => {
    console.log('HTTP server closed');
  });
});
