from dataclasses import dataclass
from typing import Optional

import environs


@dataclass
class DataBaseConfig:
    host: str
    password: str
    user: str
    database: str
    port: int = 5432

    @staticmethod
    def from_env(env: environs.Env):
        postgres_server = env.str("POSTGRES_SERVER")
        postgres_user = env.str("POSTGRES_USER")
        postgres_port = env.str("POSTGRES_PORT")
        postgres_password = env.str("POSTGRES_PASSWORD")
        postgres_db = env.str("POSTGRES_DB")

        return DataBaseConfig(host=postgres_server,
                              user=postgres_user,
                              port=postgres_port,
                              password=postgres_password,
                              database=postgres_db)


@dataclass
class Config:
    db: Optional[DataBaseConfig] = None


def load_config(path: str = None) -> Config:
    env = environs.Env()
    env.read_env(path)

    return Config(
        db=DataBaseConfig.from_env(env),
    )
