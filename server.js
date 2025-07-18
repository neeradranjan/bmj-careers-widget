// server.js - Fixed version with AWS Profile support and caching

const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const xml2js = require('xml2js');
const axios = require('axios');

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

fetch('https://bmj-careers-widget.onrender.com')
  .then(response => response.json())
  .then(data => {
    document.getElementById('output').textContent = data.message;
  })
  .catch(error => console.error('Error fetching data:', error));

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

// Save jobs to DynamoDB
async function saveJobsToDynamoDB(jobs, isUpdate = false) {
  if (!dynamoDBConnectionStatus.isConnected) {
    console.log('DynamoDB not available, skipping save operation');
    return {
      newJobsCount: 0,
      updatedJobsCount: 0,
      totalJobs: jobs.length,
      successCount: 0,
      errorCount: jobs.length,
      skipped: true
    };
  }

  const chunks = [];
  const chunkSize = 25; // DynamoDB batch write limit
  let successCount = 0;
  let errorCount = 0;

  try {
    // Get existing jobs to check for new/updated ones
    const existingJobs = await fetchJobsFromDynamoDB();
    const existingJobsMap = new Map(existingJobs.map(job => [job.id, job]));

    // Mark new and updated jobs
    const processedJobs = jobs.map(job => {
      const existingJob = existingJobsMap.get(job.id);

      if (!existingJob) {
        return { ...job, is_new: true, is_updated: false, last_seen: new Date().toISOString() };
      } else if (existingJob.modified_date !== job.modified_date) {
        return { ...job, is_new: false, is_updated: true, last_seen: new Date().toISOString() };
      } else {
        return { ...job, is_new: false, is_updated: false, last_seen: existingJob.last_seen || new Date().toISOString() };
      }
    });

    // Split into chunks for batch write
    for (let i = 0; i < processedJobs.length; i += chunkSize) {
      chunks.push(processedJobs.slice(i, i + chunkSize));
    }

    console.log(`Attempting to save ${processedJobs.length} jobs in ${chunks.length} batches...`);

    // Try batch write
    for (const chunk of chunks) {
      try {
        const params = {
          RequestItems: {
            [TABLE_NAME]: chunk.map(job => ({
              PutRequest: {
                Item: {
                  ...job,
                  id: job.id,
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

    const newJobsCount = processedJobs.filter(job => job.is_new).length;
    const updatedJobsCount = processedJobs.filter(job => job.is_updated).length;

    console.log(`DynamoDB Update Complete: ${successCount} saved, ${errorCount} failed`);

    return { newJobsCount, updatedJobsCount, totalJobs: processedJobs.length, successCount, errorCount };
  } catch (error) {
    console.error('Error in saveJobsToDynamoDB:', error);
    throw error;
  }
}

// Fetch jobs from DynamoDB
async function fetchJobsFromDynamoDB() {
  if (!dynamoDBConnectionStatus.isConnected) {
    console.log('DynamoDB not available, returning empty array');
    return [];
  }

  try {
    console.log('Fetching jobs from DynamoDB...');

    const params = {
      TableName: TABLE_NAME,
      Limit: 1000
    };

    const command = new ScanCommand(params);
    const result = await dynamodb.send(command);

    const jobs = result.Items || [];

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

// ========================================================================
// OPTIMIZED JOB LOADING WITH CACHING
// ========================================================================
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
      let jobs = [];
      let source = 'unknown';

      // Step 1: Test DynamoDB connection
      const dbAvailable = await testDynamoDBConnection();

      if (dbAvailable) {
        // Step 2: Try to fetch from DynamoDB
        jobs = await fetchJobsFromDynamoDB();

        if (jobs.length > 0) {
          console.log(`✓ Loaded ${jobs.length} jobs from DynamoDB`);
          source = 'dynamodb';
        } else {
          // DynamoDB is empty, fetch from XML and save
          console.log('DynamoDB is empty, fetching from XML feed...');
          jobs = await fetchJobsFromBMJFeed();

          if (jobs.length > 0) {
            source = 'xml_feed_initial';
            // Save to DynamoDB for future use
            await saveJobsToDynamoDB(jobs);
          }
        }
      } else {
        // DynamoDB not available, fallback to XML feed
        console.log('DynamoDB not available, using XML feed...');
        jobs = await fetchJobsFromBMJFeed();
        source = 'xml_feed_fallback';
      }

      // Update cache
      jobsCache.data = jobs;
      jobsCache.lastFetch = Date.now();
      jobsCache.source = source;

      return {
        jobs: jobs,
        source: source,
        fromCache: false
      };
    } finally {
      jobsCache.isLoading = false;
      jobsCache.loadPromise = null;
    }
  })();

  return jobsCache.loadPromise;
}

// ========================================================================
// SERVER INITIALIZATION - Pre-load jobs on startup
// ========================================================================
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

// Track API usage
async function trackAPICall(endpoint, method = 'GET') {
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

// ========================================================================
// API ENDPOINTS
// ========================================================================

// OPTIMIZED: Main API endpoint with caching
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
      newJobsCount: result.jobs.filter(j => j.is_new).length,
      updatedJobsCount: result.jobs.filter(j => j.is_updated).length,
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

// Serve HTML file (rest of the HTML serving code remains the same)
app.get('/', (req, res) => {
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

    // Optimized integration script
    const integrationScript = `

    // API Integration for BMJ Careers
    console.log('Starting BMJ Careers API integration...');

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
  console.log(`PUBLIC API ENDPOINTS:`);
  console.log(`${'='.repeat(80)}`);
  console.log(`  - GET  /jobs ....................... Get paginated job listings`);
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
