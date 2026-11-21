import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import crypto from "crypto";
import nodemailer from "nodemailer";
import { createClient } from "@supabase/supabase-js";
import cookieParser from "cookie-parser";
import { fileURLToPath } from "url";




dotenv.config();

const ACMUN_LOGO_PATH = fileURLToPath(
    new URL("./acmun.png", import.meta.url)
);

function getACMUNLogoAttachment() {
    return {
        filename: "acmun.png",
        path: ACMUN_LOGO_PATH,
        cid: "acmun-logo"
    };
}


const app = express();

const PORT =
    process.env.PORT || 3000;

app.use((req, res, next) => {
    console.log("Incoming Origin:", JSON.stringify(req.headers.origin));
    console.log("Configured FRONTEND_URL:", JSON.stringify(process.env.FRONTEND_URL));
    next();
});

app.use(
    helmet()
);

app.use(
    cors({
        origin: process.env.FRONTEND_URL,
        credentials: true,
        methods: [
            "GET",
            "POST",
            "PUT",
            "DELETE",
            "OPTIONS"
        ],
        allowedHeaders: [
            "Content-Type",
            "Authorization"
        ]
    })
);
console.log("Configured FRONTEND_URL:", JSON.stringify(process.env.FRONTEND_URL));

app.use(
    express.json({
        limit: "2mb"
    })
);

app.use(cookieParser());
/* ==========================================================
   RATE LIMITING
========================================================== */

const apiLimiter =
    rateLimit({

        windowMs:
            15 * 60 * 1000,

        max: 300,

        message: {

            error:
                "Too many requests. Please try again later."

        }

    });

app.use(
    "/api",
    apiLimiter
);



const SUPABASE_URL =
    process.env.SUPABASE_URL;

const SUPABASE_SERVICE_ROLE_KEY =
    process.env.SUPABASE_SERVICE_ROLE_KEY;


if (
    !SUPABASE_URL ||
    !SUPABASE_SERVICE_ROLE_KEY
) {

    console.error(
        "Missing Supabase environment variables."
    );


}


const supabase =
    createClient(

        SUPABASE_URL,

        SUPABASE_SERVICE_ROLE_KEY,



        {

            auth: {

                autoRefreshToken: false,

                persistSession: false

            }

        }

    );


/* ==========================================================
   SMTP
========================================================== */

const transporter =
    nodemailer.createTransport({

        host:
            process.env.SMTP_HOST,

        port:
            Number(
                process.env.SMTP_PORT
            ),

        secure:
            process.env.SMTP_SECURE ===
            "true",

        auth: {

            user:
                process.env.SMTP_USER,

            pass:
                process.env.SMTP_PASS

        }

    });


/* ==========================================================
   SMTP VERIFICATION
========================================================== */


app.get(
    "/api/test",
    (req, res) => {

        console.log(
            "TEST ROUTE HIT"
        );

        res.json({
            success: true,
            message: "Backend routes are working"
        });

    }
);



async function verifySMTP() {

    try {

        await transporter.verify();

        console.log(
            "✓ SMTP server connected successfully."
        );

    } catch (error) {

        console.error(
            "SMTP verification failed:",
            error.message
        );

    }

}


/* ==========================================================
   HASHING
========================================================== */

function createSecureHash(
    data
) {

    return crypto

        .createHmac(

            "sha256",

            process.env.HASH_SECRET

        )

        .update(

            JSON.stringify(
                data
            )

        )

        .digest(
            "hex"
        );

}


/* ==========================================================
   AUTH MIDDLEWARE
========================================================== */

/* ==========================================================
   REQUIRE ADMIN
========================================================== */

async function requireAdmin(
    req,
    res,
    next
) {

    try {

        console.log(
            "================================"
        );

        console.log(
            "AUTH MIDDLEWARE"
        );

        console.log(
            "Cookies:",
            req.cookies
        );


        const token =
            req.cookies?.acmun_access_token;


        if (!token) {

            console.log(
                "NO ACCESS TOKEN FOUND"
            );

            return res
                .status(401)
                .json({

                    success: false,

                    error:
                        "Authentication required."

                });

        }


        console.log(
            "ACCESS TOKEN FOUND"
        );


        const {

            data: {
                user
            },

            error: authError

        } =
            await supabase
                .auth
                .getUser(
                    token
                );


        if (
            authError ||
            !user
        ) {

            console.error(
                "INVALID SESSION:",
                authError?.message
            );

            return res
                .status(401)
                .json({

                    success: false,

                    error:
                        "Invalid or expired session."

                });

        }


        console.log(
            "AUTHENTICATED USER:",
            user.id
        );


        const {

            data: admin,

            error: adminError

        } =
            await supabase

                .from(
                    "admin_users"
                )

                .select(
                    "user_id, email, name, is_active"
                )

                .eq(
                    "user_id",
                    user.id
                )

                .maybeSingle();


        if (
            adminError
        ) {

            console.error(
                "ADMIN LOOKUP ERROR:",
                adminError.message
            );

            return res
                .status(500)
                .json({

                    success: false,

                    error:
                        "Unable to verify administrator."

                });

        }


        if (
            !admin
        ) {

            console.log(
                "USER IS NOT AN ADMIN"
            );

            return res
                .status(403)
                .json({

                    success: false,

                    error:
                        "Administrator access denied."

                });

        }


        if (
            !admin.is_active
        ) {

            console.log(
                "ADMIN ACCOUNT DISABLED"
            );

            return res
                .status(403)
                .json({

                    success: false,

                    error:
                        "This administrator account is disabled."

                });

        }


        req.user =
            user;

        req.admin =
            admin;


        console.log(
            "ADMIN VERIFIED:",
            admin.email
        );

        console.log(
            "================================"
        );


        next();

    } catch (error) {

        console.error(
            "AUTH MIDDLEWARE ERROR:",
            error
        );

        return res
            .status(500)
            .json({

                success: false,

                error:
                    "Authentication failed."

            });

    }

}


/* ==========================================================
   VALIDATION
========================================================== */

function validateRegistration(
    registration
) {

    if (
        !registration
    ) {

        return "Registration data is required.";

    }


    if (
        !registration.staff_advisor_name
    ) {

        return "Staff advisor name is required.";

    }


    if (
        !registration.institution_name
    ) {

        return "Institution name is required.";

    }


    if (
        !registration.delegation_name
    ) {

        return "Delegation name is required.";

    }


    if (
        !registration.head_delegate_name
    ) {

        return "Head delegate name is required.";

    }


    const delegateCount =
        Number(
            registration.number_of_delegates
        );


    if (
        !Number.isInteger(
            delegateCount
        ) ||
        delegateCount < 1
    ) {

        return "Invalid number of delegates.";

    }


    return null;

}


/* ==========================================================
   HEALTH CHECK
========================================================== */

app.get(
    "/",
    (
        req,
        res
    ) => {

        res.json({

            success: true,

            message:
                "ACMUN backend is running."

        });

    }
);


/* ==========================================================
   GET ALL REGISTRATIONS
========================================================== */

app.get(
    "/api/registrations",

    requireAdmin,

    async (
        req,
        res
    ) => {

        try {

            const {

                data,

                error

            } =
                await supabase

                    .from(
                        "registrations"
                    )

                    .select(
                        "*"
                    )

                    .order(

                        "created_at",

                        {

                            ascending: false

                        }

                    );


            if (
                error
            ) {

                throw error;

            }


            return res.json({

                success: true,

                registrations:
                    data || []

            });

        } catch (error) {

            console.error(
                "Load registrations error:",
                error
            );

            return res
                .status(500)
                .json({

                    error:
                        "Unable to load registrations."

                });

        }

    }
);


/* ==========================================================
   GET SINGLE REGISTRATION + DELEGATES
========================================================== */

app.get(
    "/api/registrations/:id",

    requireAdmin,

    async (
        req,
        res
    ) => {

        try {

            const {
                id
            } =
                req.params;


            const {

                data:
                registration,

                error:
                registrationError

            } =
                await supabase

                    .from(
                        "registrations"
                    )

                    .select(
                        "*"
                    )

                    .eq(
                        "id",
                        id
                    )

                    .single();


            if (
                registrationError ||
                !registration
            ) {

                return res
                    .status(404)
                    .json({

                        error:
                            "Registration not found."

                    });

            }


            const {

                data:
                delegates,

                error:
                delegateError

            } =
                await supabase

                    .from(
                        "delegates"
                    )

                    .select(
                        "*"
                    )

                    .eq(

                        "registration_id",

                        id

                    )

                    .order(

                        "created_at",

                        {

                            ascending: true

                        }

                    );


            if (
                delegateError
            ) {

                throw delegateError;

            }


            registration.delegates =
                delegates || [];


            return res.json({

                success: true,

                registration

            });

        } catch (error) {

            console.error(
                "Load registration error:",
                error
            );

            return res
                .status(500)
                .json({

                    error:
                        "Unable to load registration."

                });

        }

    }
);


/* ==========================================================
   UPDATE / COMPLETE REGISTRATION
========================================================== */

app.put(
    "/api/registrations/:id",

    requireAdmin,

    async (
        req,
        res
    ) => {

        try {

            const {
                id
            } =
                req.params;


            const {

                registration,

                delegates,

                complete

            } =
                req.body;


            /*
             * VALIDATE
             */

            const validationError =
                validateRegistration(
                    registration
                );


            if (
                validationError
            ) {

                return res
                    .status(400)
                    .json({

                        error:
                            validationError

                    });

            }


            if (
                !Array.isArray(
                    delegates
                )
            ) {

                return res
                    .status(400)
                    .json({

                        error:
                            "Delegates must be an array."

                    });

            }


            /*
             * CHECK REGISTRATION EXISTS
             */

            const {

                data:
                existingRegistration,

                error:
                existingError

            } =
                await supabase

                    .from(
                        "registrations"
                    )

                    .select(
                        "id, status"
                    )

                    .eq(
                        "id",
                        id
                    )

                    .single();


            if (
                existingError ||
                !existingRegistration
            ) {

                return res
                    .status(404)
                    .json({

                        error:
                            "Registration not found."

                    });

            }


            /*
             * PREPARE UPDATE DATA
             */

            const updateData =
            {

                staff_advisor_name:
                    registration.staff_advisor_name
                        ?.trim(),

                staff_advisor_email:
                    registration.staff_advisor_email
                        ?.trim(),

                staff_advisor_phone:
                    registration.staff_advisor_phone
                        ?.trim(),

                institution_name:
                    registration.institution_name
                        ?.trim(),

                institution_city:
                    registration.institution_city
                        ?.trim(),

                institution_country:
                    registration.institution_country
                        ?.trim(),

                delegation_name:
                    registration.delegation_name
                        ?.trim(),

                number_of_delegates:
                    Number(
                        registration.number_of_delegates
                    ),

                head_delegate_name:
                    registration.head_delegate_name
                        ?.trim(),

                head_delegate_committee:
                    registration.head_delegate_committee
                        ?.trim(),

                head_delegate_email:
                    registration.head_delegate_email
                        ?.trim(),

                head_delegate_phone:
                    registration.head_delegate_phone
                        ?.trim(),

                country_preference_1:
                    registration.country_preference_1
                        ?.trim(),

                country_preference_2:
                    registration.country_preference_2
                        ?.trim(),

                money:
                    Number(
                        registration.money
                    ) || 0,

                status:
                    complete
                        ? "Completed"
                        : (
                            registration.status ||
                            "Pending"
                        ),

                deadline:
                    registration.deadline
                        ? new Date(
                            registration.deadline
                        ).toISOString()
                        : null

            };


            /*
             * UPDATE REGISTRATION
             */

            const {

                error:
                updateError

            } =
                await supabase

                    .from(
                        "registrations"
                    )

                    .update(
                        updateData
                    )

                    .eq(
                        "id",
                        id
                    );


            if (
                updateError
            ) {

                throw updateError;

            }


            /*
             * UPDATE ALL DELEGATES
             */

            for (
                const delegate
                of delegates
            ) {

                if (
                    !delegate.id
                ) {

                    continue;

                }


                const delegateUpdate =
                {

                    delegate_name:
                        (
                            delegate.delegate_name ||
                            ""
                        )
                            .trim(),

                    delegate_committee:
                        (
                            delegate.delegate_committee ||
                            ""
                        )
                            .trim(),

                    delegate_email:
                        (
                            delegate.delegate_email ||
                            ""
                        )
                            .trim(),

                    delegate_phone:
                        (
                            delegate.delegate_phone ||
                            ""
                        )
                            .trim()

                };


                const {

                    error:
                    delegateUpdateError

                } =
                    await supabase

                        .from(
                            "delegates"
                        )

                        .update(
                            delegateUpdate
                        )

                        .eq(
                            "id",
                            delegate.id
                        )

                        .eq(
                            "registration_id",
                            id
                        );


                if (
                    delegateUpdateError
                ) {

                    throw delegateUpdateError;

                }

            }


            /*
             * IF NOT COMPLETING,
             * RETURN NOW
             */

            if (
                !complete
            ) {

                return res.json({

                    success: true,

                    message:
                        "Changes saved successfully."

                });

            }


            /*
             * PREVENT DUPLICATE EMAIL
             */

            if (
                existingRegistration.status ===
                "Completed"
            ) {

                return res.json({

                    success: true,

                    message:
                        "Registration was already completed."

                });

            }


            /*
             * FETCH FINAL DATA
             */

            const {

                data:
                finalRegistration,

                error:
                finalRegistrationError

            } =
                await supabase

                    .from(
                        "registrations"
                    )

                    .select(
                        "*"
                    )

                    .eq(
                        "id",
                        id
                    )

                    .single();


            if (
                finalRegistrationError
            ) {

                throw finalRegistrationError;

            }


            const {

                data:
                finalDelegates,

                error:
                finalDelegateError

            } =
                await supabase

                    .from(
                        "delegates"
                    )

                    .select(
                        "*"
                    )

                    .eq(
                        "registration_id",
                        id
                    )

                    .order(

                        "created_at",

                        {

                            ascending: true

                        }

                    );


            if (
                finalDelegateError
            ) {

                throw finalDelegateError;

            }


            /*
             * CREATE COMPLETION HASH
             */

            const completionHash =
                createSecureHash({

                    registrationId:
                        finalRegistration.id,

                    delegation:
                        finalRegistration.delegation_name,

                    institution:
                        finalRegistration.institution_name,

                    delegates:
                        finalDelegates || []

                });


            /*
             * STORE HASH
             *
             * This requires the
             * completion_hash column.
             */

            const {

                error:
                hashUpdateError

            } =
                await supabase

                    .from(
                        "registrations"
                    )

                    .update({

                        completion_hash:
                            completionHash,

                        completed_at:
                            new Date()
                                .toISOString()

                    })

                    .eq(
                        "id",
                        id
                    );


            if (
                hashUpdateError
            ) {

                throw hashUpdateError;

            }


            await sendCompletionEmail({

                registration:
                    finalRegistration,

                delegates:
                    finalDelegates

            });


            return res.json({

                success: true,

                message:
                    "Registration completed and emails sent."

            });

        } catch (error) {

            console.error(
                "Save registration error:",
                error
            );

            return res
                .status(500)
                .json({

                    success: false,

                    error:
                        "Unable to save registration."

                });

        }

    }
);


/* ==========================================================
   EMAIL HTML ESCAPING
========================================================== */

/* ==========================================================
   COMPLETION EMAIL
========================================================== */

async function sendCompletionEmail({
    registration,
    delegates = []
}) {

    if (!registration) {
        throw new Error("Registration data is required to send the completion email.");
    }

    const recipients = [
        registration.staff_advisor_email,
        registration.head_delegate_email
    ]
        .map(email => String(email || "").trim())
        .filter(email => email && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email));

    if (recipients.length === 0) {
        throw new Error("No valid email recipients found.");
    }

    const delegateRows = delegates.length
        ? delegates.map(delegate => `
            <tr>
                <td>${escapeEmailHTML(delegate.delegate_name || "—")}</td>
                <td>${escapeEmailHTML(delegate.delegate_committee || "Pending")}</td>
                <td>${escapeEmailHTML(delegate.allotment || "Pending")}</td>
            </tr>
        `).join("")
        : `
            <tr>
                <td colspan="3">No delegate details available.</td>
            </tr>
        `;

    const emailHTML = `

<!DOCTYPE html>

<html>

<head>

<style>

body {
    margin: 0;
    padding: 0;
    background: #00426f;
    font-family: Georgia, serif;
    color: #ece7dd;
}

.wrapper {
    width: 100%;
    padding: 40px 0;
}

.card {
    max-width: 700px;
    margin: auto;
    background: #171717;
    border: 1px solid #2d2d2d;
}

.hero {
    padding: 45px 20px;
    text-align: center;
    background: linear-gradient(90deg, #00426f, #173d6f);
}

.hero img {
    width: 115px;
    height: 115px;
    object-fit: contain;
    display: block;
    margin: 0 auto 24px;
}

.hero h1 {
    margin: 0;
    color: white;
    font-size: 32px;
    letter-spacing: 4px;
}

.content {
    padding: 50px;
}

h2 {
    color: white;
    font-size: 28px;
}

p {
    color: #dddddd;
    font-size: 16px;
    line-height: 1.8;
}

.summary {
    margin: 30px 0;
    padding: 25px;
    background: #101010;
    border: 1px solid #b89b4e;
}

.summary-label {
    color: #b89b4e;
    font-size: 14px;
    letter-spacing: 2px;
}

.summary-value {
    margin-top: 10px;
    color: white;
    font-size: 22px;
}

table {
    width: 100%;
    margin: 30px 0;
    border-collapse: collapse;
    color: #dddddd;
    font-size: 14px;
}

th, td {
    padding: 12px 10px;
    text-align: left;
    border-bottom: 1px solid #2d2d2d;
}

th {
    color: #b89b4e;
    font-size: 12px;
    letter-spacing: 1px;
    text-transform: uppercase;
}

.footer {
    padding: 30px;
    text-align: center;
    border-top: 1px solid #2d2d2d;
    color: #9d9d9d;
}

</style>

</head>

<body>

<div class="wrapper">

<div class="card">

<div class="hero">

 <img src='cid:acmun-logo' alt='ACMUN logo'>

 <h1>ACMUN XVII</h1>

</div>

<div class="content">

<h2>
Registration Confirmed
</h2>

<p>
Dear
<strong>
${escapeEmailHTML(registration.head_delegate_name || "Delegate")}
</strong>,
</p>

<p>
Your delegation registration has been completed successfully.
Please find the final delegation details below.
</p>

<div class="summary">

<div class="summary-label">
DELEGATION
</div>

<div class="summary-value">
${escapeEmailHTML(registration.delegation_name || "Delegation")}
</div>

<p>
<strong>Institution:</strong>
${escapeEmailHTML(registration.institution_name || "—")}
<br>
<strong>Status:</strong>
${escapeEmailHTML(registration.status || "Completed")}
</p>

</div>

<table>

<thead>
<tr>
<th>Delegate</th>
<th>Committee</th>
<th>Allotment</th>
</tr>
</thead>

<tbody>
${delegateRows}
</tbody>

</table>

<p>
If you have any questions regarding your registration or allotments,
please contact the ACMUN XVII Secretariat.
</p>

</div>

<div class="footer">

ACMUN XVII SECRETARIAT

<br><br>

© ACMUN XVII

</div>

</div>

</div>

</body>

</html>

`;

    await transporter.sendMail({
        from: process.env.SMTP_FROM || process.env.SMTP_USER,
        to: recipients.join(","),
        subject: `ACMUN XVII – Registration Confirmation | ${registration.delegation_name || "Delegation"}`,
        html: emailHTML,
        attachments: [
            getACMUNLogoAttachment()
        ]
    });

    return {
        recipients
    };
}

app.put(

    "/api/admin/registrations/:id",

    requireAdmin,

    async (
        req,
        res
    ) => {

        try {

            const {
                id
            } = req.params;


            const {
                registration,
                delegates,
                complete
            } = req.body;


            if (
                !registration ||
                !Array.isArray(
                    delegates
                )
            ) {

                return res
                    .status(400)
                    .json({

                        success: false,

                        error:
                            "Invalid registration data."

                    });

            }


            /* ================================
               UPDATE REGISTRATION
            ================================= */

            const registrationData = {

                ...registration,

                status:

                    complete
                        ? "Completed"
                        : registration.status

            };


            const {

                data: updatedRegistration,

                error: registrationError

            } =
                await supabase

                    .from(
                        "registrations"
                    )

                    .update(
                        registrationData
                    )

                    .eq(
                        "id",
                        id
                    )

                    .select()

                    .single();


            if (
                registrationError
            ) {

                throw registrationError;

            }


            /* ================================
               UPDATE DELEGATES
            ================================= */

            for (
                const delegate
                of delegates
            ) {

                const {

                    id: delegateId,

                    ...delegateData

                } =
                    delegate;


                const {

                    error: delegateError

                } =
                    await supabase

                        .from(
                            "delegates"
                        )

                        .update({

                            delegate_name:
                                delegateData.delegate_name,

                            delegate_committee:
                                delegateData.delegate_committee,

                            allotment:
                                delegateData.allotment,

                            delegate_email:
                                delegateData.delegate_email,

                            delegate_phone:
                                delegateData.delegate_phone

                        })

                        .eq(
                            "id",
                            delegateId
                        );


                if (
                    delegateError
                ) {

                    throw delegateError;

                }

            }


            /* ================================
               GET UPDATED DELEGATES
            ================================= */

            const {

                data: updatedDelegates,

                error: delegatesError

            } =
                await supabase

                    .from(
                        "delegates"
                    )

                    .select(
                        "*"
                    )

                    .eq(
                        "registration_id",
                        id
                    );


            if (
                delegatesError
            ) {

                throw delegatesError;

            }


            /* ================================
               SEND COMPLETION EMAIL
            ================================= */

            if (
                complete
            ) {

                await sendCompletionEmail({

                    registration:
                        updatedRegistration,

                    delegates:
                        updatedDelegates

                });

            }


            return res.json({

                success: true,

                registration:
                    updatedRegistration,

                delegates:
                    updatedDelegates,

                emailSent:
                    complete

            });

        } catch (error) {

            console.error(
                "UPDATE REGISTRATION ERROR:",
                error
            );

            return res
                .status(500)
                .json({

                    success: false,

                    error:
                        error.message ||
                        "Unable to update registration."

                });

        }

    }

);


app.post(

    "/api/admin/registrations/:id/payment-email",

    requireAdmin,

    async (
        req,
        res
    ) => {

        try {

            const {
                id
            } = req.params;


            const {
                amount
            } = req.body;


            if (
                !amount ||
                Number(amount) <= 0
            ) {

                return res
                    .status(400)
                    .json({

                        success: false,

                        error:
                            "A valid payment amount is required."

                    });

            }


            /* ================================
               GET REGISTRATION
            ================================= */

            const {

                data: registration,

                error

            } =
                await supabase

                    .from(
                        "registrations"
                    )

                    .select(
                        "*"
                    )

                    .eq(
                        "id",
                        id
                    )

                    .single();


            if (
                error
            ) {

                throw error;

            }


            /* ================================
               UPDATE PAYMENT AMOUNT
            ================================= */

            const {

                error: updateError

            } =
                await supabase

                    .from(
                        "registrations"
                    )

                    .update({

                        money:
                            Number(amount)

                    })

                    .eq(
                        "id",
                        id
                    );


            if (
                updateError
            ) {

                throw updateError;

            }


            /* ================================
               SEND EMAIL
            ================================= */

            await sendPaymentEmail({

                registration,

                amount:
                    Number(amount)

            });


            return res.json({

                success: true,

                message:
                    "Payment email sent."

            });

        } catch (error) {

            console.error(
                "PAYMENT EMAIL ERROR:",
                error
            );

            return res
                .status(500)
                .json({

                    success: false,

                    error:
                        "Unable to send payment email."

                });

        }

    }

);


/* ==========================================================
   PAYMENT COMPLETED EMAIL ROUTE
========================================================== */
app.post(
    "/api/admin/registrations/:id/payment-completed",
    requireAdmin,
    async (req, res) => {
        try {
            const { id } = req.params;
            const amount = Number(req.body?.amount);

            if (!Number.isFinite(amount) || amount <= 0) {
                return res.status(400).json({
                    success: false,
                    error: "A valid payment amount is required."
                });
            }

            const { data: registration, error } = await supabase
                .from("registrations")
                .select("id, head_delegate_name, head_delegate_email, staff_advisor_email, institution_name, delegation_name")
                .eq("id", id)
                .single();

            if (error || !registration) {
                return res.status(404).json({
                    success: false,
                    error: "Registration not found."
                });
            }

            await sendPaymentCompletedEmail({ registration, amount });

            return res.json({
                success: true,
                message: "Payment-completed email sent."
            });
        } catch (error) {
            console.error("PAYMENT COMPLETED EMAIL ERROR:", error);
            return res.status(500).json({
                success: false,
                error: "Unable to send payment-completed email."
            });
        }
    }
);

async function sendPaymentCompletedEmail({ registration, amount }) {
    const recipients = [
        registration.head_delegate_email,
        registration.staff_advisor_email
    ]
        .map(email => String(email || "").trim())
        .filter(email => email && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email));

    if (recipients.length === 0) {
        throw new Error("No valid email recipients found.");
    }

    const formattedAmount = `PKR ${amount.toLocaleString("en-PK", {
        minimumFractionDigits: 0,
        maximumFractionDigits: 2
    })}`;
    const recipientName = escapeEmailHTML(registration.head_delegate_name || "Delegate");
    const institution = escapeEmailHTML(registration.institution_name || "—");
    const delegation = escapeEmailHTML(registration.delegation_name || "—");

    await transporter.sendMail({
        from: process.env.SMTP_FROM,
        to: recipients.join(","),
        subject: "ACMUN XVII — Payment Completed",
        text: `Dear ${registration.head_delegate_name || "Delegate"},\n\nYour payment has been completed successfully. Amount received: ${formattedAmount}.\nInstitution: ${registration.institution_name || "—"}\nDelegation: ${registration.delegation_name || "—"}\n\nThank you,\nACMUN XVII Secretariat`,
        html: `<!DOCTYPE html>
<html><body style="margin:0;padding:32px;background:#00426f;font-family:Georgia,serif;color:#ece7dd;">
  <div style="max-width:640px;margin:auto;background:#171717;border:1px solid #2d2d2d;">
    <div style="padding:28px;text-align:center;background:#173d6f;"><img src="cid:acmun-logo" alt="ACMUN" style="width:76px;height:76px;object-fit:contain;"></div>
    <div style="padding:36px;">
      <h1 style="color:#fff;">Payment Completed</h1>
      <p>Dear <strong>${recipientName}</strong>,</p>
      <p>Your payment has been completed successfully. We have received the following amount:</p>
      <p style="padding:22px;text-align:center;background:#101010;border:1px solid #b89b4e;color:#fff;font-size:28px;"><strong>${formattedAmount}</strong></p>
      <p><strong>Institution:</strong> ${institution}</p>
      <p><strong>Delegation:</strong> ${delegation}</p>
      <p>Thank you for your payment. If you have any questions, please contact the ACMUN XVII Secretariat.</p>
    </div>
    <div style="padding:24px;text-align:center;border-top:1px solid #2d2d2d;color:#9d9d9d;">ACMUN XVII SECRETARIAT</div>
  </div>
</body></html>`,
        attachments: [getACMUNLogoAttachment()]
    });
}





function escapeEmailHTML(
    value
) {

    return String(
        value ?? ""
    )

        .replace(
            /&/g,
            "&amp;"
        )

        .replace(
            /</g,
            "&lt;"
        )

        .replace(
            />/g,
            "&gt;"
        )

        .replace(
            /"/g,
            "&quot;"
        )

        .replace(
            /'/g,
            "&#039;"
        );

}




/* ==========================================================
   ADMIN LOGIN
========================================================== */

app.post(
    "/api/auth/login",

    async (req, res) => {

        try {

            console.log(
                "LOGIN ROUTE HIT"
            );


            const {
                email,
                password
            } = req.body;


            if (
                !email ||
                !password
            ) {

                return res
                    .status(400)
                    .json({

                        success: false,

                        error:
                            "Email and password are required."

                    });

            }


            const {
                data,
                error
            } =
                await supabase
                    .auth
                    .signInWithPassword({

                        email:
                            email.trim(),

                        password

                    });


            if (
                error ||
                !data.user ||
                !data.session
            ) {

                console.error(
                    "LOGIN FAILED:",
                    error?.message
                );

                return res
                    .status(401)
                    .json({

                        success: false,

                        error:
                            "Invalid email or password."

                    });

            }


            const {

                data: admin,

                error: adminError

            } =
                await supabase

                    .from(
                        "admin_users"
                    )

                    .select(
                        "user_id, email, name, is_active"
                    )

                    .eq(
                        "user_id",
                        data.user.id
                    )

                    .maybeSingle();


            if (
                adminError
            ) {

                console.error(
                    "ADMIN CHECK ERROR:",
                    adminError.message
                );

                return res
                    .status(500)
                    .json({

                        success: false,

                        error:
                            "Unable to verify administrator."

                    });

            }


            if (
                !admin
            ) {

                return res
                    .status(403)
                    .json({

                        success: false,

                        error:
                            "This account is not an administrator."

                    });

            }


            if (
                !admin.is_active
            ) {

                return res
                    .status(403)
                    .json({

                        success: false,

                        error:
                            "This administrator account is disabled."

                    });

            }


            res.cookie(

                "acmun_access_token",

                data.session.access_token,

                {

                    httpOnly: true,

                    secure:
                        process.env.NODE_ENV ===
                        "production",

                    sameSite:
                        process.env.NODE_ENV ===
                            "production"
                            ? "none"
                            : "lax",

                    maxAge:
                        1000 *
                        60 *
                        60 *
                        24

                }

            );


            console.log(
                "LOGIN SUCCESS:",
                admin.email
            );


            return res.json({

                success: true,

                admin: {

                    name:
                        admin.name,

                    email:
                        admin.email

                }

            });

        } catch (error) {

            console.error(
                "LOGIN SERVER ERROR:",
                error
            );

            return res
                .status(500)
                .json({

                    success: false,

                    error:
                        "Internal server error."

                });

        }

    }
);

/* ==========================================================
   CHECK SESSION
========================================================== */

app.get(
    "/api/auth/session",

    requireAdmin,

    (req, res) => {

        console.log(
            "SESSION ROUTE HIT"
        );

        return res.json({

            success: true,

            admin: {

                id:
                    req.user.id,

                name:
                    req.admin.name,

                email:
                    req.admin.email

            }

        });

    }
);

/* ==========================================================
   LOGOUT
========================================================== */

app.post(
    "/api/auth/logout",

    (req, res) => {

        res.clearCookie(

            "acmun_access_token",

            {

                httpOnly: true,

                secure:
                    process.env.NODE_ENV ===
                    "production",

                sameSite:
                    process.env.NODE_ENV ===
                        "production"
                        ? "none"
                        : "lax"

            }

        );


        return res.json({

            success: true,

            message:
                "Logged out successfully."

        });

    }
);


/* ==========================================================
   PUBLIC REGISTRATION ENDPOINT
========================================================== */

app.post("/api/register", async (req, res) => {
    try {

        const {
            advisor,
            institution,
            delegation,
            headDelegate,
            delegates,
            preferences,
            totalDelegateCount
        } = req.body;
        console.log(req.body);
        /* -----------------------------
           Basic Validation
        ----------------------------- */

        if (!advisor?.name)
            return res.status(400).json({
                success: false,
                error: "Advisor name is required."
            });

        if (!institution?.name)
            return res.status(400).json({
                success: false,
                error: "Institution name is required."
            });

        if (!delegation?.name)
            return res.status(400).json({
                success: false,
                error: "Delegation name is required."
            });

        if (!headDelegate?.name)
            return res.status(400).json({
                success: false,
                error: "Head Delegate name is required."
            });

        if (!Array.isArray(delegates))
            return res.status(400).json({
                success: false,
                error: "Delegates must be an array."
            });

        /* -----------------------------
           Insert Registration
        ----------------------------- */
        const {
            data: registration,
            error: registrationError
        } = await supabase
            .from("registrations")
            .insert({
                staff_advisor_name: advisor.name.trim(),
                staff_advisor_email: advisor.email.trim(),
                staff_advisor_phone: advisor.phone.trim(),

                institution_name: institution.name.trim(),
                institution_city: institution.city.trim(),
                institution_country: institution.country.trim(),

                delegation_name: delegation.name.trim(),
                number_of_delegates: Number(totalDelegateCount),

                head_delegate_name: headDelegate.name.trim(),
                head_delegate_committee: headDelegate.committee.trim(),
                head_delegate_email: headDelegate.email.trim(),
                head_delegate_phone: headDelegate.phone.trim(),

                country_preference_1: preferences.first?.trim() || null,
                country_preference_2: preferences.second?.trim() || null,

                status: "Pending"
            })
            .select()
            .single();

        if (registrationError) {
            console.error("Registration insert failed:", registrationError);

            return res.status(500).json({
                success: false,
                error: "Unable to save registration."
            });
        }

        if (!registration) {
            return res.status(500).json({
                success: false,
                error: "Registration was not returned after saving."
            });
        }

        // Respond first.
        res.status(201).json({
            success: true,
            message: "Registration submitted successfully.",
            registrationId: registration.id
        });

        // Send emails after responding.
        setImmediate(async () => {
            try {
                await sendRegistrationReceivedEmail(registration);
                console.log(
                    "Registration email sent:",
                    registration.head_delegate_email
                );
            } catch (error) {
                console.error(
                    "Registration email failed:",
                    registration.id,
                    error
                );
            }

            try {
                await notifySecretariat(registration);
                console.log(
                    "Secretariat notification sent:",
                    registration.id
                );
            } catch (error) {
                console.error(
                    "Secretariat notification failed:",
                    registration.id,
                    error
                );
            }
        });


        console.log(delegates);

        if (delegates.length > 0) {

            const delegateRows = delegates.map(delegate => ({
                registration_id: registration.id,

                delegate_name: delegate.name,
                delegate_email: delegate.email,
                delegate_phone: delegate.phone,
                delegate_committee: delegate.committee
            }));

            const { error: delegateError } =
                await supabase
                    .from("delegates")
                    .insert(delegateRows);

            if (delegateError)
                throw delegateError;
        }

        /* -----------------------------
           Success
        ----------------------------- */

        return res.json({

            success: true,

            registrationId: registration.id,

            reference: `ACMUN-${registration.id}`

        });

    }
    catch (error) {

        console.error(error);

        return res.status(500).json({

            success: false,

            error: "Unable to submit registration."

        });

    }
});

async function sendPaymentEmail({

    registration,

    amount

}) {

    const recipients = [

        registration.head_delegate_email,

        registration.staff_advisor_email

    ]

        .filter(
            Boolean
        )

        .join(",");


    const paymentHTML = `

<!DOCTYPE html>

<html>

<head>

<style>

body {

    margin: 0;
    padding: 0;

    background:#00426f;

    font-family:
        Georgia,
        serif;

    color: #ece7dd;

}

.wrapper {

    width: 100%;
    padding: 40px 0;

}

.card {

    max-width: 700px;
    margin: auto;

    background: #171717;

    border:
        1px solid
        #2d2d2d;

}

.hero {

    padding: 45px 20px;

    text-align: center;

    background:

        linear-gradient(
            90deg,
            #00426f,
            #173d6f
        );

}

.hero img {

    width: 76px;

    height: 76px;

    object-fit: contain;

    display: block;

    margin: 0 auto;

}

.hero h1 {

    margin: 0;

    color: white;

    font-size: 32px;

    letter-spacing: 4px;

}

.content {

    padding: 50px;

}

h2 {

    color: white;

    font-size: 28px;

}

p {

    color: #dddddd;

    font-size: 16px;

    line-height: 1.8;

}

.amount {

    margin: 30px 0;

    padding: 25px;

    text-align: center;

    background: #101010;

    border:
        1px solid
        #b89b4e;

}

.amount-label {

    color: #b89b4e;

    font-size: 14px;

    letter-spacing: 2px;

}

.amount-value {

    margin-top: 10px;

    color: white;

    font-size: 32px;

}

.bank-details {

    margin: 30px 0;

    padding: 25px;

    background: #101010;

    border:
        1px solid
        #2d2d2d;

}

.bank-details-title {

    margin-bottom: 16px;

    color: #b89b4e;

    font-size: 14px;

    letter-spacing: 2px;

}

.bank-details-row {

    padding: 8px 0;

    color: #dddddd;

    font-size: 15px;

    line-height: 1.5;

    border-bottom: 1px solid #2d2d2d;

}

.bank-details-row:last-child {

    border-bottom: none;

}

.bank-details-label {

    display: inline-block;

    min-width: 150px;

    color: #9d9d9d;

}

.footer {

    padding: 30px;

    text-align: center;

    border-top:
        1px solid
        #2d2d2d;

    color: #9d9d9d;

}

</style>

</head>

<body>

<div class="wrapper">

<div class="card">

<div class="hero">

 <img src='cid:acmun-logo'>

</div>


<div class="content">

<h2>
Payment Information
</h2>


<p>

Dear
<strong>
${escapeEmailHTML(
        registration.head_delegate_name
    )}
</strong>,

</p>


<p>

This email contains the payment information
for your delegation's registration for ACMUN XVII.

</p>


<div class="amount">

<div class="amount-label">

AMOUNT PAYABLE

</div>


<div class="amount-value">

PKR ${Number(amount).toLocaleString()}

</div>

</div>

<div class="bank-details">

<div class="bank-details-title">

BANK TRANSFER DETAILS

</div>

<div class="bank-details-row">

<span class="bank-details-label">Account Holder:</span>

ASMA FALAK

</div>

<div class="bank-details-row">

<span class="bank-details-label">Bank:</span>

Meezan Bank

</div>

<div class="bank-details-row">

<span class="bank-details-label">Account Number:</span>

09030103904965

</div>

<div class="bank-details-row">

<span class="bank-details-label">IBAN:</span>

PK75MEZN0009030103904965

</div>

</div>


<p>

<strong>
Institution:
</strong>

${escapeEmailHTML(
        registration.institution_name
    )}

</p>


<p>

<strong>
Delegation:
</strong>

${escapeEmailHTML(
        registration.delegation_name
    )}

</p>


<p>

Please follow the payment instructions provided
by the ACMUN XVII Secretariat.

</p>

</div>


<div class="footer">

ACMUNI XVII SECRETARIAT

<br><br>

© ACMUN XVII

</div>

</div>

</div>

</body>

</html>

`;


    await transporter.sendMail({

        from:
            process.env.SMTP_FROM,

        to:
            recipients,

        subject:
            "ACMUN XVII — Payment Information",

        html:
            paymentHTML,

        attachments: [
            getACMUNLogoAttachment()
        ]

    });

}





async function sendRegistrationReceivedEmail(registration) {

    const recipients = [
        registration.staff_advisor_email,
        registration.head_delegate_email
    ].filter(Boolean);

    if (recipients.length === 0) {
        return;
    }

    const html = `
<!DOCTYPE html>
<html>
<body style="font-family:Arial,sans-serif;background:#f5f5f5;padding:30px;">

<div style="
max-width:700px;
margin:auto;
background:white;
padding:40px;
border-radius:10px;
">

<h1>ACMUN XVII</h1>

<p>Dear ${registration.head_delegate_name},</p>

<p>
Thank you for registering for ACMUN XVII.
</p>

<p>
Your registration has been successfully received and is now under review by the Secretariat.
</p>

<hr>

<h2>Registration Details</h2>

<p><strong>Reference:</strong> ACMUN-${registration.id}</p>

<p><strong>Institution:</strong> ${registration.institution_name}</p>

<p><strong>Delegation:</strong> ${registration.delegation_name}</p>

<p><strong>Delegates:</strong> ${registration.number_of_delegates}</p>

<hr>

<p>
You will receive another email once your registration has been reviewed.
</p>

<br>

<p>
Regards,<br>
ACMUNI XVII Secretariat
</p>

</div>

</body>
</html>
`;

    try {
        await transporter.sendMail({

            from: process.env.SMTP_FROM,

            to: recipients.join(","),

            subject: "ACMUN XVII Registration Received",

            html
        })
    } catch (error) {

        console.error(
            "Registration email failed:",
            registration.id,
            error
        );

    }

}

export async function notifySecretariat(registration) {

    await transporter.sendMail({

        from: process.env.SMTP_FROM,

        to: process.env.ADMIN_EMAIL,

        subject: `New Registration - ${registration.delegation_name}`,

        html: `

<h2>New Registration Received</h2>

<p><b>Institution:</b> ${registration.institution_name}</p>

<p><b>Delegation:</b> ${registration.delegation_name}</p>

<p><b>Head Delegate:</b> ${registration.head_delegate_name}</p>

<p><b>Email:</b> ${registration.head_delegate_email}</p>

<p><b>Delegates:</b> ${registration.number_of_delegates}</p>

<p>

Open the admin dashboard to review this registration.

</p>

`

    });

}




/* ==========================================================
   HEALTH CHECK / KEEP-ALIVE
========================================================== */

function healthResponse(req, res) {


    console.log("i am alive");
    return res.status(200).json({

        success: true,

        status: "ok",

        service: "acmun-backend",

        timestamp: new Date().toISOString()



    });

}


app.get(
    "/health",
    healthResponse
);


app.get(
    "/api/health",
    healthResponse
);


const HEALTHCHECK_URL =
    process.env.HEALTHCHECK_URL ||
    process.env.RENDER_EXTERNAL_URL ||
    process.env.APP_URL;


async function keepServerAwake() {

    if (!HEALTHCHECK_URL) {

        return;

    }


    try {

        const response = await fetch(
            `${HEALTHCHECK_URL.replace(/\/$/, "")}/health`,
            {
                method: "GET",
                headers: {
                    "User-Agent": "ACMUN-health-check"
                }
            }
        );


        if (!response.ok) {

            console.warn(
                `Health check returned HTTP ${response.status}.`
            );

        }

    } catch (error) {

        console.warn(
            "Keep-alive health check failed:",
            error.message
        );

    }

}


if (
    HEALTHCHECK_URL &&
    process.env.DISABLE_KEEP_ALIVE !== "true"
) {

    const keepAliveTimer = setInterval(
        keepServerAwake,
        15 * 1000
    );

    keepAliveTimer.unref?.();

}


app.use((req, res) => {

    console.log(
        "404 ROUTE NOT FOUND:",
        req.method,
        req.originalUrl
    );

    res.status(404).json({

        success: false,

        error: "Route not found",

        method: req.method,

        path: req.originalUrl

    });

});


export default app;
