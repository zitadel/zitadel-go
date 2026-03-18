module.exports = {
    branches: [
        {name: 'main'},
        {name: "next", prerelease: true},
    ],
    plugins: [
        ["@semantic-release/commit-analyzer", {
            releaseRules: [
                { type: "chore", scope: "deps", subject: "*security-updates*", release: "patch" },
            ],
        }],
        "@semantic-release/release-notes-generator",
        "@semantic-release/github"
    ]
};
