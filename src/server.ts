import { PrismaClient } from "@prisma/client";
import fastify, { FastifyReply, FastifyRequest } from "fastify";
import { compare, hash } from "bcrypt";
import { z } from "zod";
import jwt from "@fastify/jwt";

const app = fastify();

const databaseClient = new PrismaClient();

interface IParams {
  serialNumber?: string;
  id?: string;
}

app.register(jwt, {
  secret: process.env.JWT_SECRET_KEY as string,
});

app.addHook("onRequest", (request, reply, done) => {
  if (process.env.API_KEY !== request.headers["x-api-key"]) {
    return reply.status(403).send();
  }

  done();
});

app.decorate(
  "authenticate",
  async function (request: FastifyRequest, reply: FastifyReply) {
    try {
      await request.jwtVerify();
    } catch (err) {
      reply.send(err);
    }
  }
);

app.post("/auth/register", async (request, reply) => {
  const userSchema = z.object({
    email: z.string().email(),
    password: z.string(),
  });

  const { email, password } = userSchema.parse(request.body);

  const userAlreadyExists = await databaseClient.user.findFirst({
    where: { email },
  });

  if (userAlreadyExists) {
    return reply.status(409).send({
      message: "User already exists",
    });
  }

  const passwordHash = await hash(password, 8);

  const user = await databaseClient.user.create({
    data: {
      email,
      password: passwordHash,
    },
  });

  const token = app.jwt.sign(
    { id: user.id, email: user.email },
    {
      expiresIn: process.env.JWT_EXPIRES_IN || "1d",
    }
  );

  return reply.status(201).send({ token });
});

app.post("/auth/login", async (request, reply) => {
  const userSchema = z.object({
    email: z.string().email(),
    password: z.string(),
  });

  const { email, password } = userSchema.parse(request.body);

  const userAlreadyExists = await databaseClient.user.findFirst({
    where: { email },
  });

  if (!userAlreadyExists) {
    return reply.status(401).send({
      message: "Email or password incorrect",
    });
  }

  const passwordMatch = await compare(password, userAlreadyExists.password);

  if (!passwordMatch) {
    return reply.status(401).send({
      message: "Email or password incorrect",
    });
  }

  const token = app.jwt.sign(
    { id: userAlreadyExists.id, email: userAlreadyExists.email },
    {
      expiresIn: "7d",
    }
  );

  return reply.status(200).send({ token });
});

app.post(
  "/devices",
  { onRequest: [app.authenticate] },
  async (request, reply) => {
    const deviceSchema = z.object({
      serialNumber: z.string(),
    });

    const { serialNumber } = deviceSchema.parse(request.body);

    const deviceAlreadyExists = await databaseClient.device.findFirst({
      where: { serialNumber },
    });

    if (deviceAlreadyExists) {
      return reply.status(201).send(deviceAlreadyExists);
    }

    const device = await databaseClient.device.create({
      data: {
        serialNumber,
      },
    });

    await databaseClient.userDevice.create({
      data: {
        userId: request.user.id,
        deviceId: device.id,
      },
    });

    return reply.status(201).send(device);
  }
);

app.delete<{
  Params: IParams;
}>(
  "/devices/:id",
  { onRequest: [app.authenticate] },
  async (request, reply) => {
    const { id } = request.params;

    await databaseClient.userDevice.deleteMany({
      where: {
        userId: request.user.id,
        deviceId: id,
      },
    });

    await databaseClient.device.delete({
      where: { id },
    });

    return reply.status(200).send();
  }
);

app.get(
  "/devices",
  { onRequest: [app.authenticate] },
  async (request, reply) => {
    const userDevices = await databaseClient.userDevice.findMany({
      where: { userId: request.user.id },
    });

    const deviceIds = userDevices.map((userDevice) => userDevice.deviceId);

    const devices = await databaseClient.device.findMany({
      where: {
        id: { in: deviceIds },
      },
    });

    return reply.status(200).send(devices);
  }
);

interface IQuerystring {
  startDate?: string;
  endDate?: string;
}

app.get<{
  Params: IParams;
  Querystring: IQuerystring;
}>(
  "/devices/:serialNumber/events",
  { onRequest: [app.authenticate] },
  async (request, reply) => {
    const { serialNumber } = request.params;

    if (!serialNumber) {
      return reply
        .status(400)
        .send({ message: "Serial number must be provided" });
    }

    const device = await databaseClient.device.findFirst({
      where: { serialNumber },
    });

    if (!device) {
      return reply.status(404).send({ message: "Can not find the device" });
    }

    const queryParamsSchema = z.object({
      startDate: z.optional(z.string().datetime()),
      endDate: z.optional(z.string().datetime()),
    });

    const { startDate, endDate } = queryParamsSchema.parse(request.query);

    const queryArgs: any = {};

    if (startDate && endDate) {
      queryArgs.happenedAt = {
        lte: new Date(endDate),
        gte: new Date(startDate),
      };
    }

    if (startDate && !endDate) {
      queryArgs.happenedAt = {
        gte: new Date(startDate),
      };
    }

    if (!startDate && endDate) {
      queryArgs.happenedAt = {
        lte: new Date(endDate),
      };
    }

    const deviceEvents = await databaseClient.deviceEvent.findMany({
      where: {
        deviceId: device?.id,
        ...queryArgs,
      },
    });

    return reply.status(200).send(deviceEvents);
  }
);

app.post<{
  Params: IParams;
}>("/devices/:serialNumber/events", async (request, reply) => {
  const eventSchema = z.object({
    macAddress: z.string(),
    ipAddress: z.string().ip(),
    soilMoisture: z.number(),
    humidity: z.number(),
    temperature: z.number(),
    lighIntensity: z.number(),
    happenedAt: z.string().datetime(),
  });

  const {
    macAddress,
    ipAddress,
    soilMoisture,
    humidity,
    temperature,
    lighIntensity,
    happenedAt,
  } = eventSchema.parse(request.body);

  const { serialNumber } = request.params;

  if (!serialNumber) {
    return reply
      .status(400)
      .send({ message: "Serial number must be provided" });
  }

  let device = await databaseClient.device.findFirst({
    where: { serialNumber },
  });

  if (!device) {
    device = await databaseClient.device.create({
      data: {
        serialNumber,
      },
    });
  }

  const deviceEvent = await databaseClient.deviceEvent.create({
    data: {
      deviceId: device.id,
      macAddress,
      ipAddress,
      soilMoisture,
      humidity,
      temperature,
      lighIntensity,
      happenedAt,
    },
  });

  return reply.status(201).send(deviceEvent);
});

app
  .listen({
    host: "0.0.0.0",
    port: process.env.PORT ? Number(process.env.PORT) : 3333,
  })
  .then(() => {
    console.log("HTTP Server Running");
  });
