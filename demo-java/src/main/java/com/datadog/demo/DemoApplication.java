package com.datadog.demo;

import datadog.trace.api.Trace;

import java.util.Random;

public class DemoApplication {

    private static final Random random = new Random();

    public static void main(String[] args) {
        System.out.println("Starting Datadog Demo Application...");
        System.out.println("The application will generate traces and spans continuously.");
        System.out.println("Press Ctrl+C to stop.");
        System.out.println();

        int operationCount = 0;

        while (true) {
            try {
                operationCount++;
                System.out.println("--- Operation #" + operationCount + " ---");

                // Simulate different types of operations
                int operationType = random.nextInt(3);

                switch (operationType) {
                    case 0:
                        processOrder();
                        break;
                    case 1:
                        fetchUserData();
                        break;
                    case 2:
                        performCalculation();
                        break;
                }

                // Wait between operations
                Thread.sleep(2000 + random.nextInt(3000));

            } catch (InterruptedException e) {
                System.out.println("Application interrupted. Shutting down...");
                break;
            } catch (Exception e) {
                System.err.println("Error during operation: " + e.getMessage());
                e.printStackTrace();
            }
        }
    }

    @Trace(operationName = "process.order", resourceName = "OrderService")
    private static void processOrder() {
        System.out.println("Processing order...");

        String orderId = "ORD-" + random.nextInt(10000);
        int amount = random.nextInt(500) + 50;

        System.out.println("  Order ID: " + orderId + ", Amount: $" + amount);

        validateOrder(orderId);
        checkInventory(orderId);
        processPayment(orderId, amount);

        System.out.println("Order processed successfully\n");
    }

    @Trace(operationName = "validate.order", resourceName = "ValidationService")
    private static void validateOrder(String orderId) {
        System.out.println("  - Validating order " + orderId + "...");
        simulateWork(100, 300);
        System.out.println("  - Order validated");
    }

    @Trace(operationName = "check.inventory", resourceName = "InventoryService")
    private static void checkInventory(String orderId) {
        System.out.println("  - Checking inventory for order " + orderId + "...");
        simulateWork(50, 150);
        int itemsAvailable = random.nextInt(10) + 1;
        System.out.println("  - Inventory checked: " + itemsAvailable + " items available");
    }

    @Trace(operationName = "process.payment", resourceName = "PaymentService")
    private static void processPayment(String orderId, int amount) {
        System.out.println("  - Processing payment for order " + orderId + " ($" + amount + ")...");
        simulateWork(200, 500);

        // Simulate occasional failures
        if (random.nextInt(10) == 0) {
            System.out.println("  - Payment failed (simulated error)");
            throw new RuntimeException("Payment gateway error");
        } else {
            System.out.println("  - Payment processed successfully");
        }
    }

    @Trace(operationName = "fetch.user", resourceName = "UserService")
    private static void fetchUserData() {
        System.out.println("Fetching user data...");

        String userId = "USER-" + random.nextInt(1000);
        System.out.println("  User ID: " + userId);

        queryUserDatabase(userId);
        loadUserPreferences(userId);

        System.out.println("User data fetch completed\n");
    }

    @Trace(operationName = "database.query.user", resourceName = "UserDatabase")
    private static void queryUserDatabase(String userId) {
        System.out.println("  - Querying user database for " + userId + "...");
        simulateWork(50, 200);
        System.out.println("  - User data retrieved from database");
    }

    @Trace(operationName = "load.preferences", resourceName = "PreferenceService")
    private static void loadUserPreferences(String userId) {
        System.out.println("  - Loading user preferences for " + userId + "...");
        simulateWork(10, 50);

        // Simulate cache miss occasionally
        if (random.nextInt(5) == 0) {
            System.out.println("  - Cache miss, loading from database");
            loadPreferencesFromDatabase(userId);
        } else {
            System.out.println("  - Preferences loaded from cache");
        }
    }

    @Trace(operationName = "database.query.preferences", resourceName = "PreferenceDatabase")
    private static void loadPreferencesFromDatabase(String userId) {
        System.out.println("    - Querying preferences database for " + userId + "...");
        simulateWork(50, 150);
        System.out.println("    - Preferences retrieved from database");
    }

    @Trace(operationName = "perform.calculation", resourceName = "CalculationService")
    private static void performCalculation() {
        System.out.println("Performing calculation...");

        String calculationType = "financial";
        System.out.println("  Calculation type: " + calculationType);

        performComplexCalculation();

        double result = random.nextDouble() * 1000;
        System.out.println("  - Calculation completed: " + String.format("%.2f", result));
        System.out.println("Calculation operation completed\n");
    }

    @Trace(operationName = "complex.calculation", resourceName = "CalculationEngine")
    private static void performComplexCalculation() {
        System.out.println("  - Running complex calculation...");
        simulateWork(100, 400);
        System.out.println("  - Complex calculation finished");
    }

    private static void simulateWork(int minMs, int maxMs) {
        try {
            int sleepTime = minMs + random.nextInt(maxMs - minMs);
            Thread.sleep(sleepTime);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
