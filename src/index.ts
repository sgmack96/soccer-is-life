import { issuer } from "@openauthjs/openauth";
import { CloudflareStorage } from "@openauthjs/openauth/storage/cloudflare";
import { PasswordProvider } from "@openauthjs/openauth/provider/password";
import { PasswordUI } from "@openauthjs/openauth/ui/password";
import { createSubjects } from "@openauthjs/openauth/subject";
import { object, string } from "valibot";

const subjects = createSubjects({
  user: object({
    id: string(),
  }),
});

export default {
  fetch(request: Request, env: Env, ctx: ExecutionContext) {
    const url = new URL(request.url);
    if (url.pathname === "/") {
      const state = generateState(); // Generate a unique state parameter
      url.searchParams.set("state", state);
      url.searchParams.set("redirect_uri", url.origin + "/callback");
      url.searchParams.set("client_id", "your-client-id");
      url.searchParams.set("response_type", "code");
      url.pathname = "/authorize";
      // Store the state parameter in session storage
      if (ctx.storage) {
        ctx.storage.set('auth_state', state);
      } else {
        console.error("Storage context is undefined");
      }
      return Response.redirect(url.toString());
    } else if (url.pathname === "/callback") {
      const storedState = ctx.storage ? ctx.storage.get('auth_state') : null;
      const returnedState = url.searchParams.get('state');
      if (storedState !== returnedState) {
        return Response.json({ error: "Invalid state parameter" }, { status: 400 });
      }
      return Response.json({
        message: "OAuth flow complete!",
        params: Object.fromEntries(url.searchParams.entries()),
      });
    }

    return issuer({
      storage: CloudflareStorage({
        namespace: env.AUTH_STORAGE,
      }),
      subjects,
      providers: {
        password: PasswordProvider(
          PasswordUI({
            sendCode: async (email, code) => {
              console.log(`Sending code ${code} to ${email}`);
            },
            copy: {
              input_code: "Code (check Worker logs)",
            },
          }),
        ),
      },
      theme: {
        title: "myAuth",
        primary: "#0051c3",
        favicon: "https://workers.cloudflare.com//favicon.ico",
        logo: {
          dark: "https://imagedelivery.net/wSMYJvS3Xw-n339CbDyDIA/db1e5c92-d3a6-4ea9-3e72-155844211f00/public",
          light: "https://imagedelivery.net/wSMYJvS3Xw-n339CbDyDIA/fa5a3023-7da9-466b-98a7-4ce01ee6c700/public",
        },
      },
      success: async (ctx, value) => {
        const userId = await getOrCreateUser(env, value.email);
        ctx.subject("user", { id: userId });

        // Store the username in session storage
        const username = value.email.split('@')[0];
        if (ctx.storage) {
          ctx.storage.set('username', username);
        } else {
          console.error("Storage context is undefined");
        }

        // Redirect to the desired URL after successful authentication
        const redirectUrl = new URL("https://steviewondermack.us");
        return Response.redirect(redirectUrl.toString(), 302);
      },
    }).fetch(request, env, ctx);
  },
} satisfies ExportedHandler<Env>;

function generateState() {
  return Math.random().toString(36).substring(2);
}

async function getOrCreateUser(env: Env, email: string): Promise<string> {
  const result = await env.AUTH_DB.prepare(
    `
    INSERT INTO user (email)
    VALUES (?)
    ON CONFLICT (email) DO UPDATE SET email = email
    RETURNING id;
    `,
  )
    .bind(email)
    .first<{ id: string }>();
  if (!result) {
    throw new Error(`Unable to process user: ${email}`);
  }
  console.log(`Found or created user ${result.id} with email ${email}`);
  return result.id;
}
