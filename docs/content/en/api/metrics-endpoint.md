---
title: "Simple Metrics API Endpoint"
description: "API endpoint for retrieving finding metrics by product type with severity breakdown"
draft: false
weight: 3
---

## Simple Metrics API Endpoint

The Simple Metrics API endpoint provides finding counts by product type, broken down by severity levels and month status. This endpoint replicates the data from the UI's `/metrics/simple` page in JSON format, making it easier to integrate with other tools and dashboards.

### Endpoint Details

**URL:** `/api/v2/metrics/simple`

**Method:** `GET`

**Authentication:** Required (Token authentication)

**Authorization:** User must have `Product_Type_View` permission for the product types

### Query Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `date` | String (YYYY-MM-DD) | No | Date to filter metrics by month/year (defaults to current month) |
| `product_type_id` | Integer | No | Optional product type ID to filter metrics. If not provided, returns all accessible product types |

### Response Format

The endpoint returns an array of objects, each representing metrics for a product type:

```json
[
    {
        "product_type_id": 1,
        "product_type_name": "Web Application",
        "Total": 150,
        "S0": 5,     // Critical
        "S1": 25,    // High
        "S2": 75,    // Medium
        "S3": 40,    // Low
        "S4": 5,     // Info
        "Opened": 10,
        "Closed": 8
    },
    {
        "product_type_id": 2,
        "product_type_name": "Mobile Application",
        "Total": 89,
        "S0": 2,     // Critical
        "S1": 15,    // High
        "S2": 45,    // Medium
        "S3": 25,    // Low
        "S4": 2,     // Info
        "Opened": 7,
        "Closed": 5
    }
]
```

### Response Fields

| Field | Type | Description |
|-------|------|-------------|
| `product_type_id` | Integer | Unique identifier for the product type |
| `product_type_name` | String | Name of the product type |
| `Total` | Integer | Total number of findings for the product type in the specified month |
| `S0` | Integer | Number of Critical severity findings |
| `S1` | Integer | Number of High severity findings |
| `S2` | Integer | Number of Medium severity findings |
| `S3` | Integer | Number of Low severity findings |
| `S4` | Integer | Number of Info severity findings |
| `Opened` | Integer | Number of findings opened in the specified month |
| `Closed` | Integer | Number of findings closed in the specified month |

### Example Usage

#### Get current month metrics
```bash
GET /api/v2/metrics/simple
```

#### Get metrics for January 2024
```bash
GET /api/v2/metrics/simple?date=2024-01-15
```

#### Get metrics for a specific product type
```bash
GET /api/v2/metrics/simple?product_type_id=1
```

#### Get metrics for a specific product type and date
```bash
GET /api/v2/metrics/simple?date=2024-05-01&product_type_id=2
```

### Error Responses

#### 400 Bad Request - Invalid date characters
```json
{
    "error": "Invalid date format. Only numbers and hyphens allowed."
}
```

#### 400 Bad Request - Invalid date format
```json
{
    "error": "Invalid date format. Use YYYY-MM-DD format."
}
```

#### 400 Bad Request - Date out of range
```json
{
    "error": "Date must be between 2000-01-01 and one year from now."
}
```

#### 400 Bad Request - Invalid product_type_id format
```json
{
    "error": "Invalid product_type_id format."
}
```

#### 404 Not Found - Product type not found or access denied
```json
{
    "error": "Product type not found or access denied."
}
```

#### 403 Unauthorized - Missing or invalid authentication
```json
{
    "detail": "Authentication credentials were not provided."
}
```

#### 403 Forbidden - Insufficient permissions
```json
{
    "detail": "You do not have permission to perform this action."
}
```

### Notes

- **Authorization Model**: This endpoint uses the same authorization model as the UI's `/metrics/simple` page, ensuring consistent access control
- **Performance**: The endpoint is optimized with database aggregation instead of Python loops for better performance
- **Date Handling**: If no date is provided, the current month is used by default
- **Timezone**: All dates are handled in the server's configured timezone
- **Product Type Access**: Users will only see metrics for product types they have permission to view
- **Data Consistency**: The data returned by this API endpoint matches exactly what is displayed on the `/metrics/simple` UI page
- **Field Naming**: The API uses specific field names (`S0`, `S1`, `S2`, `S3`, `S4` for severity levels and `Total`, `Opened`, `Closed` for counts) to maintain consistency with the internal data structure
- **URL Format**: The endpoint automatically redirects requests without trailing slash to include one (301 redirect)
- **Date Validation**: The API performs two levels of date validation: first checking for valid characters (only numbers and hyphens allowed), then validating the YYYY-MM-DD format

### Use Cases

This endpoint is useful for:
- **Dashboard Integration**: Integrating DefectDojo metrics into external dashboards and reporting tools
- **Automated Reporting**: Creating automated reports showing security metrics trends over time
- **CI/CD Integration**: Monitoring security metrics as part of continuous integration pipelines
- **Executive Reporting**: Generating high-level security metrics for management reporting
- **Data Analysis**: Performing custom analysis on security finding trends and patterns
