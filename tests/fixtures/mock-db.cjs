const prisma = {
  user: {
    findUnique: async () => null,
  },
  scan: {
    findMany: async () => [],
  },
  report: {
    findFirst: async () => null,
  },
};

module.exports = { prisma };
