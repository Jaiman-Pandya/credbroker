import { defineRailway, postgres, preserve, project, redis, service, volume } from "railway/iac";

export default defineRailway(() => {
  const Postgres = postgres("Postgres", { region: "us-west2" });
  const Redis = redis("Redis", { region: "us-west2" });
  Redis.deploy = { startCommand: "/bin/sh -c \"rm -rf $RAILWAY_VOLUME_MOUNT_PATH/lost+found/ && exec docker-entrypoint.sh redis-server --requirepass $REDIS_PASSWORD --save 60 1 --dir $RAILWAY_VOLUME_MOUNT_PATH\"" };
  const redisVolume = volume("redis-volume", { alerts: { usage: { "100": {}, "80": {}, "95": {} } }, allowOnlineResize: true, region: "us-west2", sizeMB: 5000 });
  const postgresVolume = volume("postgres-volume", { alerts: { usage: { "100": {}, "80": {}, "95": {} } }, allowOnlineResize: true, region: "us-west2", sizeMB: 5000 });
  const broker = service("broker", {
    replicas: { "us-west2": 1 },
    deploy: { startCommand: "python -m credbroker.main", preDeployCommand: "python -m alembic upgrade head" },
    env: { CREDBROKER_DATABASE_URL: preserve(), CREDBROKER_DRIVE_API_BASE_URL: preserve(), CREDBROKER_HTTP_HOST: preserve(), CREDBROKER_JWT_PRIVATE_KEY_PEM: preserve(), CREDBROKER_JWT_PUBLIC_KEY_PEM: preserve(), CREDBROKER_LOCAL_MASTER_KEY_B64: preserve(), CREDBROKER_OAUTH_STATE_SECRET: preserve(), CREDBROKER_PUBLIC_BASE_URL: preserve(), CREDBROKER_REDIS_URL: preserve() },
  });
  const fakeDrive = service("fake-drive", {
    replicas: { "us-west2": 1 },
    deploy: { startCommand: "python -c \"import uvicorn; from credbroker.demo.fake_drive import app; uvicorn.run(app, host='::', port=9100, log_level='info')\"" },
  });

  return project("credbroker", {
    resources: [broker, Postgres, Redis, fakeDrive, redisVolume, postgresVolume],
  });
});
