from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    sonatype_api_token: str
    sonatype_api_base_url: str = "https://api.guide.sonatype.com"

    port_client_id: str
    port_client_secret: str
    port_api_base_url: str = "https://api.port.io/v1"

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


settings = Settings()
