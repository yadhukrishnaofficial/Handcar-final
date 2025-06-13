import requests
import math

def geocode_address(address):
    api_key = 'f95c2a61235f4365a6f22eb79ce8446a'
    url = f'https://api.opencagedata.com/geocode/v1/json?q={address}&key={api_key}'
    response = requests.get(url).json()
    if response['results']:
        latitude = response['results'][0]['geometry']['lat']
        longitude = response['results'][0]['geometry']['lng']
        return latitude, longitude
    return None, None


def haversine(lat1, lon1, lat2, lon2):
    # Radius of the Earth in kilometers
    R = 6371.0

    # Convert latitude and longitude from degrees to radians
    lat1_rad = math.radians(lat1)
    lon1_rad = math.radians(lon1)
    lat2_rad = math.radians(lat2)
    lon2_rad = math.radians(lon2)

    # Differences in coordinates
    dlat = lat2_rad - lat1_rad
    dlon = lon2_rad - lon1_rad

    # Haversine formula
    a = math.sin(dlat / 2)**2 + math.cos(lat1_rad) * math.cos(lat2_rad) * math.sin(dlon / 2)**2
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))

    # Distance in kilometers
    distance = R * c
    return distance

def get_geocoded_location(address):
    """
    This function geocodes an address and returns the latitude and longitude.
    It ensures that the geocode logic is reusable.
    """
    latitude, longitude = geocode_address(address)
    if latitude is None or longitude is None:
        raise ValueError("Invalid address. Could not geocode the address.")
    return latitude, longitude


def get_nearby_vendors(subscriber_lat, subscriber_lon):
    from .models import Services
    vendors = Services.objects.all()
    nearby = []
    for vendor in vendors:
        if vendor.latitude and vendor.longitude:
            distance = haversine(subscriber_lat, subscriber_lon, vendor.latitude, vendor.longitude)
            if distance <= 50:
                vendor.distance = round(distance, 2)
                nearby.append(vendor)
    return nearby

