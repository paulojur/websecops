import sys
import os

sys.path.append(os.path.join(os.getcwd()))

from app.core.database import engine, Base
from app.models.models import Vulnerability, Intelligence

def init_db():
    print("[-] Creating database tables...")
    Base.metadata.create_all(bind=engine)
    print("[+] Tables created successfully!")

if __name__ == "__main__":
    init_db()
