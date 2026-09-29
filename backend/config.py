DEFAULT_DETECTION_CONFIG = {
    "bruteforce_window_minutes": 5,
    "bruteforce_threshold": 5,
    "stuffing_window_minutes": 15,
    "stuffing_distinct_users": 5,
    "business_start_hour": 6,
    "business_end_hour": 22,
    "compromise_min_failures": 5,
    "compromise_window_minutes": 20,
}

CORS_ALLOW_ORIGINS = ["*"]  # tighten for production deployments
