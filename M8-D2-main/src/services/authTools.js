/** @format */

const UserModel = require("./users/schema");
const atob = require("atob");

const basicAuthMiddleware = async (req, res, next) => {
    console.log(req.headers)
    if (!req.headers.authorization) {
        const error = new Error("gib authentication bro");
        error.httpStatusCode = 401;
        next(error);
    } else {
        const [email, password] = atob(
            req.headers.authorization.split(" ")[1]
        ).split(":");
        const user = await UserModel.findByCredentials(email, password);
        if (!user) {
            const error = new Error("Wrong credentials");
            error.httpStatusCode = 401;
            next(error);
        } else {
            req.user = user;
        }

        next();
    }
};

const adminOnlyMiddleware = async (req, res, next) => {
    if (!req && req.user.role === "admin") {
        next();
    } else {
        const err = new Error("Badmin only");
        err.httpStatusCode = 403;
        next(err);
    }
};

module.exports = {
    basic: basicAuthMiddleware,
    adminOnly: adminOnlyMiddleware,
};
