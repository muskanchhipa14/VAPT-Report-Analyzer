from app.core.database import SessionLocal
from app.services.knowledge_base import seed_knowledge_base

def main():
    db = SessionLocal()
    try:
        seed_knowledge_base(db)
        print("Knowledge Base seeding script executed successfully.")
    except Exception as e:
        print(f"Error seeding Knowledge Base: {e}")
    finally:
        db.close()

if __name__ == "__main__":
    main()
