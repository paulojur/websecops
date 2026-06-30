import sys
import os

# Add backend to path
sys.path.append(os.path.join(os.getcwd(), 'app'))

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.core.database import SessionLocal
from app.models.models import Target

def test_query():
    print("Testing DB query for http://192.168.1.199:3030")
    db = SessionLocal()
    url = "http://192.168.1.199:3030"
    try:
        target = db.query(Target).filter(Target.url == url).first()
        print(f"Success. Found: {target}")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        db.close()

if __name__ == "__main__":
    test_query()
