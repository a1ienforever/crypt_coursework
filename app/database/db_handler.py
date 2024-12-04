from sqlalchemy import create_engine, text

engine = create_engine(
    "postgresql+psycopg2://crypt:crypt@localhost/crypt",
    echo=True
    )

with engine.connect() as connection:
    result = connection.execute(text(""))
    print(result.all())





