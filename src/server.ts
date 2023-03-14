import { PrismaClient } from "@prisma/client";
import fastify, { FastifyReply, FastifyRequest } from "fastify";
import { compare, hash } from "bcrypt";
import { z } from "zod";
import jwt from "@fastify/jwt";

const app = fastify();

const databaseClient = new PrismaClient();

app.register(jwt, {
  secret: process.env.JWT_SECRET_KEY as string,
});

app.addHook("onRequest", async (request, reply) => {
  // TODO: check the API KEY process.env.API_KEY with x-api-key
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
      expiresIn: "7d",
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
    // TODO: create schema

    // TODO: validate body

    // TODO: register device

    return reply.status(200).send([]);
  }
);

app.get(
  "/devices/:id/events",
  { onRequest: [app.authenticate] },
  async (request, reply) => {
    // TODO: get device events

    return reply.status(200).send([]);
  }
);

app.post("/devices/:id/events", async (request, reply) => {
  // TODO: create schema

  // TODO: validate body

  // TODO: create device event

  return reply.status(200).send([]);
});

app
  .listen({
    host: "0.0.0.0",
    port: process.env.PORT ? Number(process.env.PORT) : 3333,
  })
  .then(() => {
    console.log("HTTP Server Running");
  });
