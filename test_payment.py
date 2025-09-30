# test_payment.py
"""
Test script for NPS Integration API
"""
import requests
import json
from datetime import datetime

API_BASE_URL = "http://localhost:8000"

def print_section(title):
    """Print a formatted section header"""
    print("\n" + "="*60)
    print(f"  {title}")
    print("="*60)

def test_health_check():
    """Test the health check endpoint"""
    print_section("Testing Health Check")

    try:
        response = requests.get(f"{API_BASE_URL}/health")
        print(f"Status Code: {response.status_code}")
        print(f"Response: {json.dumps(response.json(), indent=2)}")
        return response.status_code == 200
    except Exception as e:
        print(f"❌ Error: {str(e)}")
        return False

def test_connection():
    """Test NPS connection"""
    print_section("Testing NPS Connection")

    try:
        response = requests.post(f"{API_BASE_URL}/api/test-connection")
        print(f"Status Code: {response.status_code}")
        print(f"Response: {json.dumps(response.json(), indent=2)}")
        return response.status_code == 200
    except Exception as e:
        print(f"❌ Error: {str(e)}")
        return False

def test_send_payment():
    """Test sending a payment"""
    print_section("Testing Send Payment")

    payment_data = {
        "amount": 5000.00,
        "debtor_name": "John Doe",
        "debtor_account": "0123456789",
        "debtor_bvn": "12345678901",
        "creditor_name": "Jane Smith",
        "creditor_account": "9876543210",
        "creditor_bvn": "10987654321",
        "narration": "Test payment transaction"
    }

    print(f"\nPayment Request:")
    print(json.dumps(payment_data, indent=2))

    try:
        response = requests.post(
            f"{API_BASE_URL}/api/send-payment",
            json=payment_data,
            headers={"Content-Type": "application/json"}
        )

        print(f"\nStatus Code: {response.status_code}")
        print(f"Response: {json.dumps(response.json(), indent=2)}")

        if response.status_code == 200:
            print("\n✅ Payment sent successfully!")
            return True
        else:
            print("\n❌ Payment failed!")
            return False

    except Exception as e:
        print(f"❌ Error: {str(e)}")
        return False

def test_invalid_payment():
    """Test payment validation"""
    print_section("Testing Payment Validation")

    # Test with invalid BVN (too short)
    invalid_payment = {
        "amount": 1000.00,
        "debtor_name": "John Doe",
        "debtor_account": "0123456789",
        "debtor_bvn": "123456",  # Invalid - too short
        "creditor_name": "Jane Smith",
        "creditor_account": "9876543210",
        "creditor_bvn": "10987654321"
    }

    print(f"\nInvalid Payment Request (short BVN):")
    print(json.dumps(invalid_payment, indent=2))

    try:
        response = requests.post(
            f"{API_BASE_URL}/api/send-payment",
            json=invalid_payment,
            headers={"Content-Type": "application/json"}
        )

        print(f"\nStatus Code: {response.status_code}")
        print(f"Response: {json.dumps(response.json(), indent=2)}")

        if response.status_code == 422:  # Validation error expected
            print("\n✅ Validation working correctly!")
            return True
        else:
            print("\n❌ Validation should have failed!")
            return False

    except Exception as e:
        print(f"❌ Error: {str(e)}")
        return False

def run_all_tests():
    """Run all tests"""
    print("\n")
    print("╔" + "="*58 + "╗")
    print("║" + " "*15 + "NPS INTEGRATION TEST SUITE" + " "*16 + "║")
    print("╚" + "="*58 + "╝")
    print(f"\nTest started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    results = {
        "Health Check": test_health_check(),
        "Connection Test": test_connection(),
        "Send Payment": test_send_payment(),
        "Payment Validation": test_invalid_payment()
    }

    # Print summary
    print_section("Test Summary")
    passed = sum(results.values())
    total = len(results)

    for test_name, result in results.items():
        status = "✅ PASSED" if result else "❌ FAILED"
        print(f"{test_name:25} {status}")

    print(f"\n{'='*60}")
    print(f"Total: {passed}/{total} tests passed")
    print(f"{'='*60}\n")

    return passed == total

if __name__ == "__main__":
    import sys

    # Check if server is running
    try:
        requests.get(f"{API_BASE_URL}/health", timeout=2)
    except requests.exceptions.RequestException:
        print("\n❌ Error: API server is not running!")
        print("Please start the server first with: python app.py")
        sys.exit(1)

    # Run tests
    success = run_all_tests()
    sys.exit(0 if success else 1)