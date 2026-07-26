from sqlalchemy.orm import Session
from app.models.report import Report


def create_report(db: Session, filename: str):
    report = Report(filename=filename)
    db.add(report)
    db.commit()
    db.refresh(report)
    return report


def get_reports(db: Session):
    return db.query(Report).all()


def get_report(db: Session, report_id: int):
    return db.query(Report).filter(Report.id == report_id).first()


def update_report(db: Session, report_id: int, status: str):
    report = get_report(db, report_id)

    if report:
        report.status = status
        db.commit()
        db.refresh(report)

    return report


def delete_report(db: Session, report_id: int):
    report = get_report(db, report_id)

    if report:
        db.delete(report)
        db.commit()

    return report