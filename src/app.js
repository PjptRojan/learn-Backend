import express from "express";
import cors from "cors";
import cookieParser from "cookie-parser";
//cookie parser is used for accessing cookies from client's browser with our server and set the cookie in their browser too. Secure cookies can only be kept by the server and removed by server.

const app = express();

app.use(
  cors({
    origin: process.env.CORS_ORIGIN,
    credentials: true,
  })
);

app.use(
  express.json({
    // keeping a limit on json files size to accept by the server
    limit: "16kb",
  })
);

app.use(
  express.urlencoded({
    // this is to let the server know about the data's coming from the URL of the browser about some special characters like a space.
    extended: true,
    limit: "16kb",
  })
);

app.use(express.static("public")); // if we want to store some files, folders in the server. this creates a public folder or assets

app.use(cookieParser());

// routes import
import userRouter from "./routes/user.routes.js";

// routes declaration
app.get("/", (req, res) => {
  res.send("hello");
});
app.use("/api/v1/users", userRouter);

//http://localhost:8000/api/v1/users/register

export { app };
