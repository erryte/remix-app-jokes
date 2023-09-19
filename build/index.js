var __defProp = Object.defineProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: !0 });
};

// app/entry.server.tsx
var entry_server_exports = {};
__export(entry_server_exports, {
  default: () => handleRequest
});
import { PassThrough } from "node:stream";
import { createReadableStreamFromReadable } from "@remix-run/node";
import { RemixServer } from "@remix-run/react";
import isbot from "isbot";
import { renderToPipeableStream } from "react-dom/server";
import { jsx } from "react/jsx-runtime";
var ABORT_DELAY = 5e3;
function handleRequest(request, responseStatusCode, responseHeaders, remixContext, loadContext) {
  return isbot(request.headers.get("user-agent")) ? handleBotRequest(
    request,
    responseStatusCode,
    responseHeaders,
    remixContext
  ) : handleBrowserRequest(
    request,
    responseStatusCode,
    responseHeaders,
    remixContext
  );
}
function handleBotRequest(request, responseStatusCode, responseHeaders, remixContext) {
  return new Promise((resolve, reject) => {
    let shellRendered = !1, { pipe, abort } = renderToPipeableStream(
      /* @__PURE__ */ jsx(
        RemixServer,
        {
          context: remixContext,
          url: request.url,
          abortDelay: ABORT_DELAY
        }
      ),
      {
        onAllReady() {
          shellRendered = !0;
          let body = new PassThrough(), stream = createReadableStreamFromReadable(body);
          responseHeaders.set("Content-Type", "text/html"), resolve(
            new Response(stream, {
              headers: responseHeaders,
              status: responseStatusCode
            })
          ), pipe(body);
        },
        onShellError(error) {
          reject(error);
        },
        onError(error) {
          responseStatusCode = 500, shellRendered && console.error(error);
        }
      }
    );
    setTimeout(abort, ABORT_DELAY);
  });
}
function handleBrowserRequest(request, responseStatusCode, responseHeaders, remixContext) {
  return new Promise((resolve, reject) => {
    let shellRendered = !1, { pipe, abort } = renderToPipeableStream(
      /* @__PURE__ */ jsx(
        RemixServer,
        {
          context: remixContext,
          url: request.url,
          abortDelay: ABORT_DELAY
        }
      ),
      {
        onShellReady() {
          shellRendered = !0;
          let body = new PassThrough(), stream = createReadableStreamFromReadable(body);
          responseHeaders.set("Content-Type", "text/html"), resolve(
            new Response(stream, {
              headers: responseHeaders,
              status: responseStatusCode
            })
          ), pipe(body);
        },
        onShellError(error) {
          reject(error);
        },
        onError(error) {
          responseStatusCode = 500, shellRendered && console.error(error);
        }
      }
    );
    setTimeout(abort, ABORT_DELAY);
  });
}

// app/root.tsx
var root_exports = {};
__export(root_exports, {
  ErrorBoundary: () => ErrorBoundary,
  default: () => App,
  links: () => links,
  meta: () => meta
});
import {
  isRouteErrorResponse,
  Links,
  LiveReload,
  Meta,
  Outlet,
  Scripts,
  useRouteError
} from "@remix-run/react";

// app/styles/global-large.css
var global_large_default = "/build/_assets/global-large-QRYATTZA.css";

// app/styles/global-medium.css
var global_medium_default = "/build/_assets/global-medium-Y44SOM2R.css";

// app/styles/global.css
var global_default = "/build/_assets/global-T2ZU2ZRM.css";

// app/root.tsx
import { jsx as jsx2, jsxs } from "react/jsx-runtime";
var links = () => [
  { rel: "stylesheet", href: global_default },
  {
    rel: "stylesheet",
    href: global_medium_default,
    media: "print, (min-width: 640px)"
  },
  {
    rel: "stylesheet",
    href: global_large_default,
    media: "screen and (min-width: 1024px)"
  }
], meta = () => {
  let description = "Learn Remix and laugh at the same time!";
  return [
    { name: "description", content: description },
    { name: "twitter:description", content: description },
    { title: "Remix: So great, it's funny!" }
  ];
};
function Document({
  children,
  title
}) {
  return /* @__PURE__ */ jsxs("html", { lang: "en", children: [
    /* @__PURE__ */ jsxs("head", { children: [
      /* @__PURE__ */ jsx2("meta", { charSet: "utf-8" }),
      /* @__PURE__ */ jsx2(
        "meta",
        {
          name: "viewport",
          content: "width=device-width, initial-scale=1"
        }
      ),
      /* @__PURE__ */ jsx2("meta", { name: "keywords", content: "Remix,jokes" }),
      /* @__PURE__ */ jsx2(
        "meta",
        {
          name: "twitter:image",
          content: "https://remix-jokes.lol/social.png"
        }
      ),
      /* @__PURE__ */ jsx2(
        "meta",
        {
          name: "twitter:card",
          content: "summary_large_image"
        }
      ),
      /* @__PURE__ */ jsx2("meta", { name: "twitter:creator", content: "@remix_run" }),
      /* @__PURE__ */ jsx2("meta", { name: "twitter:site", content: "@remix_run" }),
      /* @__PURE__ */ jsx2("meta", { name: "twitter:title", content: "Remix Jokes" }),
      /* @__PURE__ */ jsx2(Meta, {}),
      title ? /* @__PURE__ */ jsx2("title", { children: title }) : null,
      /* @__PURE__ */ jsx2(Links, {})
    ] }),
    /* @__PURE__ */ jsxs("body", { children: [
      children,
      /* @__PURE__ */ jsx2(Scripts, {}),
      /* @__PURE__ */ jsx2(LiveReload, {})
    ] })
  ] });
}
function App() {
  return /* @__PURE__ */ jsx2(Document, { children: /* @__PURE__ */ jsx2(Outlet, {}) });
}
function ErrorBoundary() {
  let error = useRouteError();
  if (console.error(error), isRouteErrorResponse(error))
    return /* @__PURE__ */ jsx2(
      Document,
      {
        title: `${error.status} ${error.statusText}`,
        children: /* @__PURE__ */ jsx2("div", { className: "error-container", children: /* @__PURE__ */ jsxs("h1", { children: [
          error.status,
          " ",
          error.statusText
        ] }) })
      }
    );
  let errorMessage = error instanceof Error ? error.message : "Unknown error";
  return /* @__PURE__ */ jsx2(Document, { title: "Uh-oh!", children: /* @__PURE__ */ jsxs("div", { className: "error-container", children: [
    /* @__PURE__ */ jsx2("h1", { children: "App Error" }),
    /* @__PURE__ */ jsx2("pre", { children: errorMessage })
  ] }) });
}

// app/routes/jokes.$jokeId.tsx
var jokes_jokeId_exports = {};
__export(jokes_jokeId_exports, {
  ErrorBoundary: () => ErrorBoundary2,
  action: () => action,
  default: () => JokeRoute,
  loader: () => loader,
  meta: () => meta2
});
import { json, redirect as redirect2 } from "@remix-run/node";
import {
  isRouteErrorResponse as isRouteErrorResponse2,
  useLoaderData,
  useParams,
  useRouteError as useRouteError2
} from "@remix-run/react";

// app/components/joke.tsx
import { Form, Link } from "@remix-run/react";
import { jsx as jsx3, jsxs as jsxs2 } from "react/jsx-runtime";
function JokeDisplay({
  canDelete = !0,
  isOwner,
  joke
}) {
  return /* @__PURE__ */ jsxs2("div", { children: [
    /* @__PURE__ */ jsx3("p", { children: "Here's your hilarious joke:" }),
    /* @__PURE__ */ jsx3("p", { children: joke.content }),
    /* @__PURE__ */ jsxs2(Link, { to: ".", children: [
      '"',
      joke.name,
      '" Permalink'
    ] }),
    isOwner ? /* @__PURE__ */ jsx3(Form, { method: "post", children: /* @__PURE__ */ jsx3(
      "button",
      {
        className: "button",
        disabled: !canDelete,
        name: "intent",
        type: "submit",
        value: "delete",
        children: "Delete"
      }
    ) }) : null
  ] });
}

// app/utils/db.server.ts
import { PrismaClient } from "@prisma/client";

// app/utils/singleton.server.ts
var singleton = (name, valueFactory) => {
  let g = global;
  return g.__singletons ??= {}, g.__singletons[name] ??= valueFactory(), g.__singletons[name];
};

// app/utils/db.server.ts
var db = singleton(
  "prisma",
  () => new PrismaClient()
);

// app/utils/session.server.ts
import {
  createCookieSessionStorage,
  redirect
} from "@remix-run/node";
import bcrypt from "bcryptjs";
async function register({
  password,
  username
}) {
  let passwordHash = await bcrypt.hash(password, 10);
  return { id: (await db.user.create({
    data: { passwordHash, username }
  })).id, username };
}
async function login({
  username,
  password
}) {
  let user = await db.user.findUnique({
    where: { username }
  });
  return !user || !await bcrypt.compare(
    password,
    user.passwordHash
  ) ? null : { id: user.id, username };
}
var sessionSecret = process.env.SESSION_SECRET;
if (!sessionSecret)
  throw new Error("SESSION_SECRET must be set");
var storage = createCookieSessionStorage({
  cookie: {
    name: "RJ_session",
    // normally you want this to be `secure: true`
    // but that doesn't work on localhost for Safari
    // https://web.dev/when-to-use-local-https/
    secure: !0,
    secrets: [sessionSecret],
    sameSite: "lax",
    path: "/",
    maxAge: 60 * 60 * 24 * 30,
    httpOnly: !0
  }
});
function getUserSession(request) {
  return storage.getSession(request.headers.get("Cookie"));
}
async function getUserId(request) {
  let userId = (await getUserSession(request)).get("userId");
  return !userId || typeof userId != "string" ? null : userId;
}
async function requireUserId(request, redirectTo = new URL(request.url).pathname) {
  let userId = (await getUserSession(request)).get("userId");
  if (!userId || typeof userId != "string") {
    let searchParams = new URLSearchParams([
      ["redirectTo", redirectTo]
    ]);
    throw redirect(`/login?${searchParams}`);
  }
  return userId;
}
async function getUser(request) {
  let userId = await getUserId(request);
  if (typeof userId != "string")
    return null;
  let user = await db.user.findUnique({
    select: { id: !0, username: !0 },
    where: { id: userId }
  });
  if (!user)
    throw await logout(request);
  return user;
}
async function logout(request) {
  let session = await getUserSession(request);
  return redirect("/login", {
    headers: {
      "Set-Cookie": await storage.destroySession(session)
    }
  });
}
async function createUserSession(userId, redirectTo) {
  let session = await storage.getSession();
  return session.set("userId", userId), redirect(redirectTo, {
    headers: {
      "Set-Cookie": await storage.commitSession(session)
    }
  });
}

// app/routes/jokes.$jokeId.tsx
import { jsx as jsx4, jsxs as jsxs3 } from "react/jsx-runtime";
var meta2 = ({
  data
}) => {
  let { description, title } = data ? {
    description: `Enjoy the "${data.joke.name}" joke and much more`,
    title: `"${data.joke.name}" joke`
  } : { description: "No joke found", title: "No joke" };
  return [
    { name: "description", content: description },
    { name: "twitter:description", content: description },
    { title }
  ];
}, loader = async ({
  params,
  request
}) => {
  let userId = await getUserId(request), joke = await db.joke.findUnique({
    where: { id: params.jokeId }
  });
  if (!joke)
    throw new Response("What a joke! Not found.", {
      status: 404
    });
  return json({
    isOwner: userId === joke.jokesterId,
    joke
  });
}, action = async ({
  params,
  request
}) => {
  let form = await request.formData();
  if (form.get("intent") !== "delete")
    throw new Response(
      `The intent ${form.get("intent")} is not supported`,
      { status: 400 }
    );
  let userId = await requireUserId(request), joke = await db.joke.findUnique({
    where: { id: params.jokeId }
  });
  if (!joke)
    throw new Response("Can't delete what does not exist", {
      status: 404
    });
  if (joke.jokesterId !== userId)
    throw new Response(
      "Pssh, nice try. That's not your joke",
      { status: 403 }
    );
  return await db.joke.delete({ where: { id: params.jokeId } }), redirect2("/jokes");
};
function JokeRoute() {
  let data = useLoaderData();
  return /* @__PURE__ */ jsx4(JokeDisplay, { isOwner: data.isOwner, joke: data.joke });
}
function ErrorBoundary2() {
  let { jokeId } = useParams(), error = useRouteError2();
  if (console.error(error), isRouteErrorResponse2(error)) {
    if (error.status === 400)
      return /* @__PURE__ */ jsx4("div", { className: "error-container", children: "What you're trying to do is not allowed." });
    if (error.status === 403)
      return /* @__PURE__ */ jsxs3("div", { className: "error-container", children: [
        'Sorry, but "',
        jokeId,
        '" is not your joke.'
      ] });
    if (error.status === 404)
      return /* @__PURE__ */ jsxs3("div", { className: "error-container", children: [
        'Huh? What the heck is "',
        jokeId,
        '"?'
      ] });
  }
  return /* @__PURE__ */ jsxs3("div", { className: "error-container", children: [
    'There was an error loading joke by the id "$',
    jokeId,
    '". Sorry.'
  ] });
}

// app/routes/jokes._index.tsx
var jokes_index_exports = {};
__export(jokes_index_exports, {
  ErrorBoundary: () => ErrorBoundary3,
  default: () => JokesIndexRoute,
  loader: () => loader2
});
import { json as json2 } from "@remix-run/node";
import {
  isRouteErrorResponse as isRouteErrorResponse3,
  Link as Link2,
  useLoaderData as useLoaderData2,
  useRouteError as useRouteError3
} from "@remix-run/react";
import { jsx as jsx5, jsxs as jsxs4 } from "react/jsx-runtime";
var loader2 = async () => {
  let count = await db.joke.count(), randomRowNumber = Math.floor(Math.random() * count), [randomJoke] = await db.joke.findMany({
    skip: randomRowNumber,
    take: 1
  });
  if (!randomJoke)
    throw new Response("No random joke found", {
      status: 404
    });
  return json2({ randomJoke });
};
function JokesIndexRoute() {
  let data = useLoaderData2();
  return /* @__PURE__ */ jsxs4("div", { children: [
    /* @__PURE__ */ jsx5("p", { children: "Here's a random joke:" }),
    /* @__PURE__ */ jsx5("p", { children: data.randomJoke.content }),
    /* @__PURE__ */ jsxs4(Link2, { to: data.randomJoke.id, children: [
      '"',
      data.randomJoke.name,
      '" Permalink'
    ] })
  ] });
}
function ErrorBoundary3() {
  let error = useRouteError3();
  return console.error(error), isRouteErrorResponse3(error) && error.status === 404 ? /* @__PURE__ */ jsxs4("div", { className: "error-container", children: [
    /* @__PURE__ */ jsx5("p", { children: "There are no jokes to display." }),
    /* @__PURE__ */ jsx5(Link2, { to: "new", children: "Add your own" })
  ] }) : /* @__PURE__ */ jsx5("div", { className: "error-container", children: "I did a whoopsies." });
}

// app/routes/jokes[.]rss.tsx
var jokes_rss_exports = {};
__export(jokes_rss_exports, {
  loader: () => loader3
});
function escapeCdata(s) {
  return s.replace(/\]\]>/g, "]]]]><![CDATA[>");
}
function escapeHtml(s) {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#039;");
}
var loader3 = async ({
  request
}) => {
  let jokes = await db.joke.findMany({
    include: { jokester: { select: { username: !0 } } },
    orderBy: { createdAt: "desc" },
    take: 100
  }), host = request.headers.get("X-Forwarded-Host") ?? request.headers.get("host");
  if (!host)
    throw new Error("Could not determine domain URL.");
  let jokesUrl = `${`${host.includes("localhost") ? "http" : "https"}://${host}`}/jokes`, rssString = `
    <rss xmlns:blogChannel="${jokesUrl}" version="2.0">
      <channel>
        <title>Remix Jokes</title>
        <link>${jokesUrl}</link>
        <description>Some funny jokes</description>
        <language>en-us</language>
        <generator>Kody the Koala</generator>
        <ttl>40</ttl>
        ${jokes.map(
    (joke) => `
            <item>
              <title><![CDATA[${escapeCdata(
      joke.name
    )}]]></title>
              <description><![CDATA[A funny joke called ${escapeHtml(
      joke.name
    )}]]></description>
              <author><![CDATA[${escapeCdata(
      joke.jokester.username
    )}]]></author>
              <pubDate>${joke.createdAt.toUTCString()}</pubDate>
              <link>${jokesUrl}/${joke.id}</link>
              <guid>${jokesUrl}/${joke.id}</guid>
            </item>
          `.trim()
  ).join(`
`)}
      </channel>
    </rss>
  `.trim();
  return new Response(rssString, {
    headers: {
      "Cache-Control": `public, max-age=${60 * 10}, s-maxage=${60 * 60 * 24}`,
      "Content-Type": "application/xml",
      "Content-Length": String(
        Buffer.byteLength(rssString)
      )
    }
  });
};

// app/routes/jokes.new.tsx
var jokes_new_exports = {};
__export(jokes_new_exports, {
  ErrorBoundary: () => ErrorBoundary4,
  action: () => action2,
  default: () => NewJokeRoute,
  loader: () => loader4
});
import { json as json4, redirect as redirect3 } from "@remix-run/node";
import {
  Form as Form2,
  isRouteErrorResponse as isRouteErrorResponse4,
  Link as Link3,
  useActionData,
  useNavigation,
  useRouteError as useRouteError4
} from "@remix-run/react";

// app/utils/request.server.ts
import { json as json3 } from "@remix-run/node";
var badRequest = (data) => json3(data, { status: 400 });

// app/routes/jokes.new.tsx
import { jsx as jsx6, jsxs as jsxs5 } from "react/jsx-runtime";
var loader4 = async ({
  request
}) => {
  if (!await getUserId(request))
    throw new Response("Unauthorized", { status: 401 });
  return json4({});
};
function validateJokeContent(content) {
  if (content.length < 10)
    return "That joke is too short";
}
function validateJokeName(name) {
  if (name.length < 3)
    return "That joke's name is too short";
}
var action2 = async ({
  request
}) => {
  let userId = await requireUserId(request), form = await request.formData(), content = form.get("content"), name = form.get("name");
  if (typeof content != "string" || typeof name != "string")
    return badRequest({
      fieldErrors: null,
      fields: null,
      formError: "Form not submitted correctly."
    });
  let fieldErrors = {
    content: validateJokeContent(content),
    name: validateJokeName(name)
  }, fields = { content, name };
  if (Object.values(fieldErrors).some(Boolean))
    return badRequest({
      fieldErrors,
      fields,
      formError: null
    });
  let joke = await db.joke.create({
    data: { ...fields, jokesterId: userId }
  });
  return redirect3(`/jokes/${joke.id}`);
};
function NewJokeRoute() {
  let actionData = useActionData(), navigation = useNavigation();
  if (navigation.formData) {
    let content = navigation.formData.get("content"), name = navigation.formData.get("name");
    if (typeof content == "string" && typeof name == "string" && !validateJokeContent(content) && !validateJokeName(name))
      return /* @__PURE__ */ jsx6(
        JokeDisplay,
        {
          canDelete: !1,
          isOwner: !0,
          joke: { name, content }
        }
      );
  }
  return /* @__PURE__ */ jsxs5("div", { children: [
    /* @__PURE__ */ jsx6("p", { children: "Add your own hilarious joke" }),
    /* @__PURE__ */ jsxs5(Form2, { method: "post", children: [
      /* @__PURE__ */ jsxs5("div", { children: [
        /* @__PURE__ */ jsxs5("label", { children: [
          "Name:",
          " ",
          /* @__PURE__ */ jsx6(
            "input",
            {
              defaultValue: actionData?.fields?.name,
              name: "name",
              type: "text",
              "aria-invalid": Boolean(
                actionData?.fieldErrors?.name
              ),
              "aria-errormessage": actionData?.fieldErrors?.name ? "name-error" : void 0
            }
          )
        ] }),
        actionData?.fieldErrors?.name ? /* @__PURE__ */ jsx6(
          "p",
          {
            className: "form-validation-error",
            id: "name-error",
            role: "alert",
            children: actionData.fieldErrors.name
          }
        ) : null
      ] }),
      /* @__PURE__ */ jsxs5("div", { children: [
        /* @__PURE__ */ jsxs5("label", { children: [
          "Content:",
          " ",
          /* @__PURE__ */ jsx6(
            "textarea",
            {
              defaultValue: actionData?.fields?.content,
              name: "content",
              "aria-invalid": Boolean(
                actionData?.fieldErrors?.content
              ),
              "aria-errormessage": actionData?.fieldErrors?.content ? "content-error" : void 0
            }
          )
        ] }),
        actionData?.fieldErrors?.content ? /* @__PURE__ */ jsx6(
          "p",
          {
            className: "form-validation-error",
            id: "content-error",
            role: "alert",
            children: actionData.fieldErrors.content
          }
        ) : null
      ] }),
      /* @__PURE__ */ jsxs5("div", { children: [
        actionData?.formError ? /* @__PURE__ */ jsx6(
          "p",
          {
            className: "form-validation-error",
            role: "alert",
            children: actionData.formError
          }
        ) : null,
        /* @__PURE__ */ jsx6("button", { type: "submit", className: "button", children: "Add" })
      ] })
    ] })
  ] });
}
function ErrorBoundary4() {
  let error = useRouteError4();
  return console.error(error), isRouteErrorResponse4(error) && error.status === 401 ? /* @__PURE__ */ jsxs5("div", { className: "error-container", children: [
    /* @__PURE__ */ jsx6("p", { children: "You must be logged in to create a joke." }),
    /* @__PURE__ */ jsx6(Link3, { to: "/login", children: "Login" })
  ] }) : /* @__PURE__ */ jsx6("div", { className: "error-container", children: "Something unexpected went wrong. Sorry about that." });
}

// app/routes/_index.tsx
var index_exports = {};
__export(index_exports, {
  default: () => IndexRoute,
  links: () => links2
});
import { Link as Link4 } from "@remix-run/react";

// app/styles/index.css
var styles_default = "/build/_assets/index-FG4AY5TC.css";

// app/routes/_index.tsx
import { jsx as jsx7, jsxs as jsxs6 } from "react/jsx-runtime";
var links2 = () => [
  { rel: "stylesheet", href: styles_default }
];
function IndexRoute() {
  return /* @__PURE__ */ jsx7("div", { className: "container", children: /* @__PURE__ */ jsxs6("div", { className: "content", children: [
    /* @__PURE__ */ jsxs6("h1", { children: [
      "Remix ",
      /* @__PURE__ */ jsx7("span", { children: "Jokes!" })
    ] }),
    /* @__PURE__ */ jsx7("nav", { children: /* @__PURE__ */ jsxs6("ul", { children: [
      /* @__PURE__ */ jsx7("li", { children: /* @__PURE__ */ jsx7(Link4, { to: "jokes", children: "Read Jokes" }) }),
      /* @__PURE__ */ jsx7("li", { children: /* @__PURE__ */ jsx7(Link4, { reloadDocument: !0, to: "/jokes.rss", children: "RSS" }) })
    ] }) })
  ] }) });
}

// app/routes/logout.tsx
var logout_exports = {};
__export(logout_exports, {
  action: () => action3,
  loader: () => loader5
});
import { redirect as redirect4 } from "@remix-run/node";
var action3 = async ({
  request
}) => logout(request), loader5 = async () => redirect4("/");

// app/routes/jokes.tsx
var jokes_exports = {};
__export(jokes_exports, {
  default: () => JokesRoute,
  links: () => links3,
  loader: () => loader6
});
import { json as json5 } from "@remix-run/node";
import {
  Form as Form3,
  Link as Link5,
  Outlet as Outlet2,
  useLoaderData as useLoaderData3
} from "@remix-run/react";

// app/styles/jokes.css
var jokes_default = "/build/_assets/jokes-DQCG33RC.css";

// app/routes/jokes.tsx
import { jsx as jsx8, jsxs as jsxs7 } from "react/jsx-runtime";
var links3 = () => [
  { rel: "stylesheet", href: jokes_default }
], loader6 = async ({
  request
}) => {
  let jokeListItems = await db.joke.findMany({
    orderBy: { createdAt: "desc" },
    select: { id: !0, name: !0 },
    take: 5
  }), user = await getUser(request);
  return json5({ jokeListItems, user });
};
function JokesRoute() {
  let data = useLoaderData3();
  return /* @__PURE__ */ jsxs7("div", { className: "jokes-layout", children: [
    /* @__PURE__ */ jsx8("header", { className: "jokes-header", children: /* @__PURE__ */ jsxs7("div", { className: "container", children: [
      /* @__PURE__ */ jsx8("h1", { className: "home-link", children: /* @__PURE__ */ jsxs7(
        Link5,
        {
          to: "/",
          title: "Remix Jokes",
          "aria-label": "Remix Jokes",
          children: [
            /* @__PURE__ */ jsx8("span", { className: "logo", children: "\u{1F92A}" }),
            /* @__PURE__ */ jsx8("span", { className: "logo-medium", children: "J\u{1F92A}KES" })
          ]
        }
      ) }),
      data.user ? /* @__PURE__ */ jsxs7("div", { className: "user-info", children: [
        /* @__PURE__ */ jsx8("span", { children: `Hi ${data.user.username}` }),
        /* @__PURE__ */ jsx8(Form3, { action: "/logout", method: "post", children: /* @__PURE__ */ jsx8("button", { type: "submit", className: "button", children: "Logout" }) })
      ] }) : /* @__PURE__ */ jsx8(Link5, { to: "/login", children: "Login" })
    ] }) }),
    /* @__PURE__ */ jsx8("main", { className: "jokes-main", children: /* @__PURE__ */ jsxs7("div", { className: "container", children: [
      /* @__PURE__ */ jsxs7("div", { className: "jokes-list", children: [
        /* @__PURE__ */ jsx8(Link5, { to: ".", children: "Get a random joke" }),
        /* @__PURE__ */ jsx8("p", { children: "Here are a few more jokes to check out:" }),
        /* @__PURE__ */ jsx8("ul", { children: data.jokeListItems.map(
          ({ id, name }) => /* @__PURE__ */ jsx8("li", { children: /* @__PURE__ */ jsx8(Link5, { prefetch: "intent", to: id, children: name }) }, id)
        ) }),
        /* @__PURE__ */ jsx8(Link5, { to: "new", className: "button", children: "Add your own" })
      ] }),
      /* @__PURE__ */ jsx8("div", { className: "jokes-outlet", children: /* @__PURE__ */ jsx8(Outlet2, {}) })
    ] }) }),
    /* @__PURE__ */ jsx8("footer", { className: "jokes-footer", children: /* @__PURE__ */ jsx8("div", { className: "container", children: /* @__PURE__ */ jsx8(Link5, { reloadDocument: !0, to: "/jokes.rss", children: "RSS" }) }) })
  ] });
}

// app/routes/login.tsx
var login_exports = {};
__export(login_exports, {
  action: () => action4,
  default: () => Login,
  links: () => links4,
  meta: () => meta3
});
import {
  Form as Form4,
  Link as Link6,
  useActionData as useActionData2,
  useSearchParams
} from "@remix-run/react";

// app/styles/login.css
var login_default = "/build/_assets/login-RXC4QZMY.css";

// app/routes/login.tsx
import { jsx as jsx9, jsxs as jsxs8 } from "react/jsx-runtime";
var links4 = () => [
  { rel: "stylesheet", href: login_default }
], meta3 = () => {
  let description = "Login to submit your own jokes to Remix Jokes!";
  return [
    { name: "description", content: description },
    { name: "twitter:description", content: description },
    { title: "Remix Jokes | Login" }
  ];
};
function validateUsername(username) {
  if (username.length < 3)
    return "Usernames must be at least 3 characters long";
}
function validatePassword(password) {
  if (password.length < 6)
    return "Passwords must be at least 6 characters long";
}
function validateUrl(url) {
  return ["/jokes", "/", "https://remix.run"].includes(url) ? url : "/jokes";
}
var action4 = async ({
  request
}) => {
  let form = await request.formData(), loginType = form.get("loginType"), password = form.get("password"), username = form.get("username"), redirectTo = validateUrl(
    form.get("redirectTo") || "/jokes"
  );
  if (typeof loginType != "string" || typeof password != "string" || typeof username != "string")
    return badRequest({
      fieldErrors: null,
      fields: null,
      formError: "Form not submitted correctly."
    });
  let fields = { loginType, password, username }, fieldErrors = {
    password: validatePassword(password),
    username: validateUsername(username)
  };
  if (Object.values(fieldErrors).some(Boolean))
    return badRequest({
      fieldErrors,
      fields,
      formError: null
    });
  switch (loginType) {
    case "login": {
      let user = await login({ username, password });
      return console.log({ user }), user ? createUserSession(user.id, redirectTo) : badRequest({
        fieldErrors: null,
        fields,
        formError: "Username/Password combination is incorrect"
      });
    }
    case "register": {
      if (await db.user.findFirst({
        where: { username }
      }))
        return badRequest({
          fieldErrors: null,
          fields,
          formError: `User with username ${username} already exists`
        });
      let user = await register({ username, password });
      return user ? createUserSession(user.id, redirectTo) : badRequest({
        fieldErrors: null,
        fields,
        formError: "Something went wrong trying to create a new user."
      });
    }
    default:
      return badRequest({
        fieldErrors: null,
        fields,
        formError: "Login type invalid"
      });
  }
};
function Login() {
  let actionData = useActionData2(), [searchParams] = useSearchParams();
  return /* @__PURE__ */ jsxs8("div", { className: "container", children: [
    /* @__PURE__ */ jsxs8("div", { className: "content", "data-light": "", children: [
      /* @__PURE__ */ jsx9("h1", { children: "Login" }),
      /* @__PURE__ */ jsxs8(Form4, { method: "post", children: [
        /* @__PURE__ */ jsx9(
          "input",
          {
            type: "hidden",
            name: "redirectTo",
            value: searchParams.get("redirectTo") ?? void 0
          }
        ),
        /* @__PURE__ */ jsxs8("fieldset", { children: [
          /* @__PURE__ */ jsx9("legend", { className: "sr-only", children: "Login or Register?" }),
          /* @__PURE__ */ jsxs8("label", { children: [
            /* @__PURE__ */ jsx9(
              "input",
              {
                type: "radio",
                name: "loginType",
                value: "login",
                defaultChecked: !actionData?.fields?.loginType || actionData?.fields?.loginType === "login"
              }
            ),
            " ",
            "Login"
          ] }),
          /* @__PURE__ */ jsxs8("label", { children: [
            /* @__PURE__ */ jsx9(
              "input",
              {
                type: "radio",
                name: "loginType",
                value: "register",
                defaultChecked: actionData?.fields?.loginType === "register"
              }
            ),
            " ",
            "Register"
          ] })
        ] }),
        /* @__PURE__ */ jsxs8("div", { children: [
          /* @__PURE__ */ jsx9("label", { htmlFor: "username-input", children: "Username" }),
          /* @__PURE__ */ jsx9(
            "input",
            {
              type: "text",
              id: "username-input",
              name: "username",
              defaultValue: actionData?.fields?.username,
              "aria-invalid": Boolean(
                actionData?.fieldErrors?.username
              ),
              "aria-errormessage": actionData?.fieldErrors?.username ? "username-error" : void 0
            }
          ),
          actionData?.fieldErrors?.username ? /* @__PURE__ */ jsx9(
            "p",
            {
              className: "form-validation-error",
              role: "alert",
              id: "username-error",
              children: actionData.fieldErrors.username
            }
          ) : null
        ] }),
        /* @__PURE__ */ jsxs8("div", { children: [
          /* @__PURE__ */ jsx9("label", { htmlFor: "password-input", children: "Password" }),
          /* @__PURE__ */ jsx9(
            "input",
            {
              id: "password-input",
              name: "password",
              type: "password",
              defaultValue: actionData?.fields?.password,
              "aria-invalid": Boolean(
                actionData?.fieldErrors?.password
              ),
              "aria-errormessage": actionData?.fieldErrors?.password ? "password-error" : void 0
            }
          ),
          actionData?.fieldErrors?.password ? /* @__PURE__ */ jsx9(
            "p",
            {
              className: "form-validation-error",
              role: "alert",
              id: "password-error",
              children: actionData.fieldErrors.password
            }
          ) : null
        ] }),
        /* @__PURE__ */ jsx9("div", { id: "form-error-message", children: actionData?.formError ? /* @__PURE__ */ jsx9(
          "p",
          {
            className: "form-validation-error",
            role: "alert",
            children: actionData.formError
          }
        ) : null }),
        /* @__PURE__ */ jsx9("button", { type: "submit", className: "button", children: "Submit" })
      ] })
    ] }),
    /* @__PURE__ */ jsx9("div", { className: "links", children: /* @__PURE__ */ jsxs8("ul", { children: [
      /* @__PURE__ */ jsx9("li", { children: /* @__PURE__ */ jsx9(Link6, { to: "/", children: "Home" }) }),
      /* @__PURE__ */ jsx9("li", { children: /* @__PURE__ */ jsx9(Link6, { to: "/jokes", children: "Jokes" }) })
    ] }) })
  ] });
}

// server-assets-manifest:@remix-run/dev/assets-manifest
var assets_manifest_default = { entry: { module: "/build/entry.client-6XQNETWD.js", imports: ["/build/_shared/chunk-FXYY623G.js", "/build/_shared/chunk-Q3IECNXJ.js"] }, routes: { root: { id: "root", parentId: void 0, path: "", index: void 0, caseSensitive: void 0, module: "/build/root-MEAZ64HF.js", imports: void 0, hasAction: !1, hasLoader: !1, hasErrorBoundary: !0 }, "routes/_index": { id: "routes/_index", parentId: "root", path: void 0, index: !0, caseSensitive: void 0, module: "/build/routes/_index-7UJUBUPN.js", imports: void 0, hasAction: !1, hasLoader: !1, hasErrorBoundary: !1 }, "routes/jokes": { id: "routes/jokes", parentId: "root", path: "jokes", index: void 0, caseSensitive: void 0, module: "/build/routes/jokes-XKN7GEKI.js", imports: ["/build/_shared/chunk-QVTEGN3F.js", "/build/_shared/chunk-PGOH7JLP.js", "/build/_shared/chunk-VAWQIAN7.js"], hasAction: !1, hasLoader: !0, hasErrorBoundary: !1 }, "routes/jokes.$jokeId": { id: "routes/jokes.$jokeId", parentId: "routes/jokes", path: ":jokeId", index: void 0, caseSensitive: void 0, module: "/build/routes/jokes.$jokeId-45GYWHRD.js", imports: ["/build/_shared/chunk-CWOGSDJQ.js"], hasAction: !0, hasLoader: !0, hasErrorBoundary: !0 }, "routes/jokes._index": { id: "routes/jokes._index", parentId: "routes/jokes", path: void 0, index: !0, caseSensitive: void 0, module: "/build/routes/jokes._index-C4M7SJFX.js", imports: void 0, hasAction: !1, hasLoader: !0, hasErrorBoundary: !0 }, "routes/jokes.new": { id: "routes/jokes.new", parentId: "routes/jokes", path: "new", index: void 0, caseSensitive: void 0, module: "/build/routes/jokes.new-3JJCH7D4.js", imports: ["/build/_shared/chunk-XYRB6XSM.js", "/build/_shared/chunk-CWOGSDJQ.js"], hasAction: !0, hasLoader: !0, hasErrorBoundary: !0 }, "routes/jokes[.]rss": { id: "routes/jokes[.]rss", parentId: "root", path: "jokes.rss", index: void 0, caseSensitive: void 0, module: "/build/routes/jokes[.]rss-7KGE2CWI.js", imports: void 0, hasAction: !1, hasLoader: !0, hasErrorBoundary: !1 }, "routes/login": { id: "routes/login", parentId: "root", path: "login", index: void 0, caseSensitive: void 0, module: "/build/routes/login-4ZTX7ONV.js", imports: ["/build/_shared/chunk-XYRB6XSM.js", "/build/_shared/chunk-QVTEGN3F.js", "/build/_shared/chunk-VAWQIAN7.js"], hasAction: !0, hasLoader: !1, hasErrorBoundary: !1 }, "routes/logout": { id: "routes/logout", parentId: "root", path: "logout", index: void 0, caseSensitive: void 0, module: "/build/routes/logout-GPTXG6BX.js", imports: void 0, hasAction: !0, hasLoader: !0, hasErrorBoundary: !1 } }, version: "6de6266a", hmr: void 0, url: "/build/manifest-6DE6266A.js" };

// server-entry-module:@remix-run/dev/server-build
var mode = "production", assetsBuildDirectory = "public/build", future = {}, publicPath = "/build/", entry = { module: entry_server_exports }, routes = {
  root: {
    id: "root",
    parentId: void 0,
    path: "",
    index: void 0,
    caseSensitive: void 0,
    module: root_exports
  },
  "routes/jokes.$jokeId": {
    id: "routes/jokes.$jokeId",
    parentId: "routes/jokes",
    path: ":jokeId",
    index: void 0,
    caseSensitive: void 0,
    module: jokes_jokeId_exports
  },
  "routes/jokes._index": {
    id: "routes/jokes._index",
    parentId: "routes/jokes",
    path: void 0,
    index: !0,
    caseSensitive: void 0,
    module: jokes_index_exports
  },
  "routes/jokes[.]rss": {
    id: "routes/jokes[.]rss",
    parentId: "root",
    path: "jokes.rss",
    index: void 0,
    caseSensitive: void 0,
    module: jokes_rss_exports
  },
  "routes/jokes.new": {
    id: "routes/jokes.new",
    parentId: "routes/jokes",
    path: "new",
    index: void 0,
    caseSensitive: void 0,
    module: jokes_new_exports
  },
  "routes/_index": {
    id: "routes/_index",
    parentId: "root",
    path: void 0,
    index: !0,
    caseSensitive: void 0,
    module: index_exports
  },
  "routes/logout": {
    id: "routes/logout",
    parentId: "root",
    path: "logout",
    index: void 0,
    caseSensitive: void 0,
    module: logout_exports
  },
  "routes/jokes": {
    id: "routes/jokes",
    parentId: "root",
    path: "jokes",
    index: void 0,
    caseSensitive: void 0,
    module: jokes_exports
  },
  "routes/login": {
    id: "routes/login",
    parentId: "root",
    path: "login",
    index: void 0,
    caseSensitive: void 0,
    module: login_exports
  }
};
export {
  assets_manifest_default as assets,
  assetsBuildDirectory,
  entry,
  future,
  mode,
  publicPath,
  routes
};
