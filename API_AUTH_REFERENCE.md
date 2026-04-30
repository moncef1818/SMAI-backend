# SMAI Backend API & WebSocket Documentation

This document provides a comprehensive reference for all REST API endpoints and WebSocket channels available in the SMAI Backend application.

## Authentication Methods

The API supports two types of authentication depending on the client:

1.  **JWT Authentication (Users/Web App)**
    *   Used by the frontend application and users.
    *   Header format: `Authorization: Bearer <access_token>`
2.  **API Key Authentication (Agents/Hosts)**
    *   Used by hosts/agents to ingest events.
    *   Header format: `Authorization: ApiKey <api_key>`

---

## 1. Authentication & User Management (`/api/auth/`)

### Register User
*   **URL**: `/api/auth/register/`
*   **Method**: `POST`
*   **Auth**: None required
*   **Payload**:
    ```json
    {
      "username": "johndoe",
      "email": "john@example.com",
      "password": "SecurePassword123",
      "password_confirm": "SecurePassword123",
      "mac_address": "00:1A:2B:3C:4D:5E"
    }
    ```
    *Note: The `mac_address` must correspond to an already registered host.*
*   **Response**: `201 Created`
    ```json
    {
      "user": {
        "id": 1,
        "username": "johndoe",
        "email": "john@example.com",
        "first_name": "",
        "last_name": "",
        "role": "employee",
        "host_hostname": "workstation-1",
        "group_id": null,
        "group_name": null
      },
      "refresh": "<refresh_token>",
      "access": "<access_token>"
    }
    ```

### Login
*   **URL**: `/api/auth/login/`
*   **Method**: `POST`
*   **Auth**: None required
*   **Payload**:
    ```json
    {
      "username": "johndoe",
      "password": "SecurePassword123"
    }
    ```
*   **Response**: `200 OK` (Returns user details and tokens)

### Refresh Token
*   **URL**: `/api/token/refresh/` or `/api/auth/token/refresh/`
*   **Method**: `POST`
*   **Auth**: None required
*   **Payload**:
    ```json
    {
      "refresh": "<refresh_token>"
    }
    ```
*   **Response**: `200 OK` (Returns new access token)

### Get/Update Current User
*   **URL**: `/api/auth/user/` (or `/api/auth/me/`)
*   **Method**: `GET` / `PATCH`
*   **Auth**: `Bearer <token>`
*   **PATCH Payload** (partial updates allowed):
    ```json
    {
      "first_name": "John",
      "last_name": "Doe",
      "email": "new.email@example.com"
    }
    ```
*   **Response**: `200 OK` (Returns updated user profile)

### Logout
*   **URL**: `/api/auth/logout/`
*   **Method**: `POST`
*   **Auth**: `Bearer <token>`
*   **Payload**:
    ```json
    {
      "refresh": "<refresh_token>"
    }
    ```
*   **Response**: `200 OK`

---

## 2. Administrator Operations (`/api/auth/` & `/api/groups/`)

*Requires Admin Role (`Bearer <token>`)*

### List All Users
*   **URL**: `/api/auth/users/`
*   **Method**: `GET`
*   **Response**: `200 OK` (Array of users)

### Elevate User Role
*   **URL**: `/api/auth/users/elevate/`
*   **Method**: `POST`
*   **Payload**:
    ```json
    {
      "user_id": 1,
      "new_role": "group_leader"  // or "admin"
    }
    ```
*   **Response**: `200 OK`

### Assign Host to Group
*   **URL**: `/api/auth/hosts/assign-group/`
*   **Method**: `POST`
*   **Payload**:
    ```json
    {
      "host_id": "<host_uuid>",
      "group_id": 1
    }
    ```
*   **Response**: `200 OK`

---

## 3. Host Management (`/api/hosts/` & `/api/agents/`)

### Register Host
*   **URL**: `/api/hosts/register/`
*   **Method**: `POST`
*   **Auth**: None required
*   **Payload**:
    ```json
    {
      "hostname": "workstation-01",
      "ip_address": "192.168.1.50",
      "mac_address": "00:1A:2B:3C:4D:5E",
      "os": "Windows 11"
    }
    ```
*   **Response**: `201 Created` or `200 OK`
    ```json
    {
      "host_id": "<uuid>",
      "api_key": "<hex_api_key>",
      "created": true
    }
    ```

### Host Heartbeat
*   **URL**: `/api/hosts/heartbeat/`
*   **Method**: `POST`
*   **Auth**: None required
*   **Payload**:
    ```json
    {
      "mac_address": "00:1A:2B:3C:4D:5E"
    }
    ```
*   **Response**: `200 OK` (`{"status": "ok"}`)

### List Hosts
*   **URL**: `/api/hosts/list/`
*   **Method**: `GET`
*   **Auth**: `Bearer <token>` (Admin lists all, Group Leader lists their group)
*   **Response**: `200 OK` (Array of hosts)

### Host Details
*   **URL**: `/api/hosts/details/<uuid>/`
*   **Method**: `GET`
*   **Auth**: `Bearer <token>` (Access restricted by role/group)
*   **Response**: `200 OK` (Host object)

### Host Agents Status Overview
*   **URL**: `/api/hosts/agents/` (also mapped to `/api/agents/`)
*   **Method**: `GET`
*   **Auth**: `Bearer <token>`
*   **Response**: `200 OK`
    ```json
    {
      "total_hosts": 15,
      "status_counts": [{"status": "online", "count": 10}],
      "hosts": []
    }
    ```

---

## 4. Group Management (`/api/groups/`)

### List Groups
*   **URL**: `/api/groups/list/` (also `/api/auth/groups/` for admins)
*   **Method**: `GET`
*   **Auth**: `Bearer <token>`
*   **Response**: `200 OK` (Array of groups including member hosts)

### Create Group (Admin)
*   **URL**: `/api/groups/create/`
*   **Method**: `POST`
*   **Auth**: `Bearer <token>`
*   **Payload**:
    ```json
    {
      "name": "Engineering",
      "description": "Software Engineering Team"
    }
    ```
*   **Response**: `201 Created`

### Assign Host to Group (Admin)
*   **URL**: `/api/groups/assign-host/<group_uuid>/`
*   **Method**: `POST`
*   **Auth**: `Bearer <token>`
*   **Payload**:
    ```json
    {
      "host_id": "<host_uuid>"
    }
    ```
*   **Response**: `200 OK`

### Assign Leader to Group (Admin)
*   **URL**: `/api/groups/assign-leader/<group_uuid>/`
*   **Method**: `POST`
*   **Auth**: `Bearer <token>`
*   **Payload**:
    ```json
    {
      "leader_id": "<user_uuid>"
    }
    ```
*   **Response**: `200 OK`

---

## 5. Event Ingestion (`/api/events/`)

### Ingest Event
*   **URL**: `/api/events/`
*   **Method**: `POST`
*   **Auth**: `ApiKey <host_api_key>`
*   **Payload**:
    ```json
    {
      "source_type": "agent", // or "browser"
      "log_source": "NetworkMonitor", // "FileMonitor", "BrowserExtension", etc.
      "event_type": "suspicious_activity",
      "payload": {
        // Dynamic JSON payload based on log_source
      }
    }
    ```
*   **Response**: `202 Accepted` (`{"status": "queued"}`)

---

## 6. Incident Management & Dashboard (`/api/incidents/` & Dashboard endpoints)

All endpoints require `Bearer <token>`. Responses are filtered based on the user's role (Admin sees all, Group Leader sees their group, Employee sees their own host).

### List Incidents
*   **URL**: `/api/incidents/`
*   **Method**: `GET`
*   **Query Parameters** (Optional filtering):
    *   `severity`: `info`, `low`, `medium`, `high`, `critical`
    *   `threat_source`: `rule`, `ml`
    *   `host_id`: `<uuid>`
    *   `group_id`: `<id>`
    *   `log_source`: `NetworkMonitor`, `BrowserExtension`, etc.
*   **Response**: `200 OK` (Array of incidents)

### Incident Summary / Dashboard Overview
*   **URL**: `/api/incidents/summary/` (also mapped to `/api/overview/`)
*   **Method**: `GET`
*   **Response**: `200 OK`
    ```json
    {
      "total_incidents": 100,
      "severity_counts": [{"severity": "high", "count": 10}],
      "threat_source_counts": [{"threat_source": "ml", "count": 60}],
      "top_hosts": [{"host__hostname": "workstation-1", "count": 45}],
      "network_incident_count": 30
    }
    ```

### Incident Alerts (High/Critical only)
*   **URL**: `/api/incidents/alerts/` (also mapped to `/api/alerts/`)
*   **Method**: `GET`
*   **Response**: `200 OK` (Array of high/critical incidents)

### Network Incidents
*   **URL**: `/api/incidents/network/` (also mapped to `/api/network/`)
*   **Method**: `GET`
*   **Response**: `200 OK` (Array of incidents originating from `NetworkMonitor`)

---

## 7. WebSocket APIs (`/ws/incidents/`)

Provides real-time notifications for new incidents. Connections are authenticated automatically using the session or token context, and users are grouped by their role to receive relevant incidents.

*   **Endpoint**: `ws://<backend_host>/ws/incidents/`
*   **Connection**: Requires standard Django session/token auth (handled via `AuthMiddlewareStack`).

### Client Actions (Send to Server)

1.  **Get Recent Incidents**
    ```json
    {
      "action": "get_recent"
    }
    ```
2.  **Acknowledge Incident**
    ```json
    {
      "action": "acknowledge",
      "incident_id": "<uuid>"
    }
    ```

### Server Responses (Receive from Server)

1.  **Recent Incidents List** (Received automatically on connect or when requested)
    ```json
    {
      "type": "recent_incidents",
      "incidents": [
        {
          "incident_id": "<uuid>",
          "host_id": "<uuid>",
          "host_hostname": "workstation-1",
          "threat_type": "ML-BruteForce",
          "severity": "high",
          "created_at": "2026-04-30T12:00:00Z"
        }
      ]
    }
    ```

2.  **New Incident Notification** (Pushed in real-time)
    ```json
    {
      "type": "new_incident",
      "incident": {
        "incident_id": "<uuid>",
        "host_id": "<uuid>",
        "host_hostname": "workstation-2",
        "threat_type": "Rule-SuspiciousProcess",
        "severity": "medium",
        "created_at": "2026-04-30T12:01:00Z"
      }
    }
    ```
